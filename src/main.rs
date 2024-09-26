use axum::{
    extract::{Path, State},
    http::{header, StatusCode},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
    Router,
};
use axum_extra::{
    extract::{cookie::Cookie, CookieJar, Form},
    response::Html,
};
use axum_htmx::{AutoVaryLayer, HxRefresh};
use clap::Parser;
use minijinja::{context, Environment, Value};
use serde::{Deserialize, Serialize};
use sqlx::{
    migrate::MigrateError,
    sqlite::{SqliteConnectOptions, SqlitePool},
    types::Json,
    QueryBuilder,
};
use std::{collections::BTreeMap, net::SocketAddr, path::PathBuf, str::FromStr};
use time::{format_description::well_known::Rfc3339, Duration, OffsetDateTime};
use tower_http::services::ServeDir;

mod token;
use token::Token;

const MAX_OPTIONS: usize = 128;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Bind address (default: 127.0.0.1:3000)
    #[arg(long, default_value = "127.0.0.1:3000")]
    bind: SocketAddr,

    /// SQLite database URL
    #[arg(long, default_value = "sqlite://database.sqlite")]
    db_url: String,
}

#[derive(Clone)]
struct AppState {
    tpl: Environment<'static>,
    db: SqlitePool,
}

impl AppState {
    fn log_minijinja_error(&self, prefix: &str, err: minijinja::Error) {
        eprintln!("{}: {:#}", prefix, err);
        let mut err = &err as &dyn std::error::Error;
        while let Some(next_err) = err.source() {
            eprintln!("    caused by: {:#}", next_err);
            err = next_err;
        }
    }
    pub fn render(&self, template: &str, context: Value) -> Result<String, Response> {
        let tpl = self.tpl.get_template(template).map_err(|e| {
            self.log_minijinja_error(&format!("Failed to load template: '{}'", template), e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to prepare a response",
            )
                .into_response()
        })?;
        tpl.render(context).map_err(|e| {
            self.log_minijinja_error(&format!("Failed to render template: '{}'", template), e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to prepare a response",
            )
                .into_response()
        })
    }
}

async fn migrate(pool: &SqlitePool) -> Result<(), MigrateError> {
    sqlx::migrate!("./migrations/").run(pool).await
}

fn slugify(value: String) -> String {
    value
        .to_lowercase()
        .split(|c: char| c.is_whitespace() || c.is_ascii_punctuation() || c.is_control())
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("-")
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Initialize SQLite database
    let pool_options = SqliteConnectOptions::from_str(&args.db_url)?
        .create_if_missing(true)
        .busy_timeout(std::time::Duration::from_micros(1000))
        .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
        .auto_vacuum(sqlx::sqlite::SqliteAutoVacuum::Full)
        .optimize_on_close(true, None)
        .foreign_keys(true);
    let pool = SqlitePool::connect_with(pool_options).await?;
    migrate(&pool).await?;

    // Initialize Tera
    let mut tpl = Environment::new();
    tpl.add_filter("slugify", slugify);
    minijinja_contrib::add_to_environment(&mut tpl);
    minijinja_embed::load_templates!(&mut tpl);

    let compression = tower_http::compression::CompressionLayer::new()
        .gzip(true)
        .br(true)
        .zstd(true);

    // Create a new Axum router
    let app = Router::new()
        .route("/", get(index))
        .route("/poll/new", get(new_poll_form).post(create_poll))
        .route("/poll/new/new-option", get(new_poll_new_option))
        .route("/poll/new/del-option", get(new_poll_del_option))
        .route("/poll/:token/view", get(view_poll))
        .route("/poll/:token/new_voter", post(new_voter))
        .route("/poll/:token/vote", post(vote))
        .route("/poll/:token/admin/edit", get(edit_poll))
        .route("/poll/:token/admin/share", get(share_admin))
        .route("/poll/:token/admin/:admin_token", get(login_admin))
        .nest_service("/static", ServeDir::new(PathBuf::from("static")))
        .layer(compression)
        .layer(AutoVaryLayer)
        .with_state(AppState { tpl, db: pool });

    println!("Listening on {}", args.bind);

    // Start the server
    let listener = tokio::net::TcpListener::bind(&args.bind).await.unwrap();
    axum::serve(listener, app).await.unwrap();

    Ok(())
}

async fn index(State(state): State<AppState>) -> impl IntoResponse {
    let html = state.render("index.html", context! {}).unwrap();

    (
        [
            (header::CONTENT_TYPE, "text/html"),
            (header::CACHE_CONTROL, "no-cache"),
        ],
        Html(html),
    )
}

async fn new_poll_form(State(state): State<AppState>) -> impl IntoResponse {
    let html = state
        .render(
            "new_poll.html",
            context! {
                title => "Create New Poll",
                options => &vec!(None::<String>, None, None),
            },
        )
        .unwrap();

    (
        [
            (header::CONTENT_TYPE, "text/html"),
            (header::CACHE_CONTROL, "no-cache"),
        ],
        Html(html),
    )
}

#[derive(Deserialize)]
struct NewPollForm {
    title: String,
    description: String,
    options: Vec<String>,
}

// todo: better error message when no options are given!
async fn create_poll(
    State(state): State<AppState>,
    Form(new_poll): Form<NewPollForm>,
) -> impl IntoResponse {
    let token = Token::new();
    let admin_token = Token::new();

    // Generate expiration date
    let expiration = OffsetDateTime::now_utc() + Duration::days(90);

    // Gather options
    let options: Vec<_> = new_poll
        .options
        .iter()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();

    if options.len() > MAX_OPTIONS {
        eprintln!("Failed to create poll: too many options: {}", options.len());
        return (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to create poll",
        )
            .into_response();
    }

    let Ok(mut tx) = state.db.begin().await else {
        eprintln!("Failed to create poll: transaction error");
        return (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to create poll",
        )
            .into_response();
    };

    // Insert the new poll into the database
    if let Err(e) = sqlx::query(
        "INSERT INTO polls (token, admin_token, title, description, expiration) VALUES (?, ?, ?, ?, ?)"
    )
        .bind(token.to_string())
        .bind(admin_token.to_string())
        .bind(&new_poll.title)
        .bind(&new_poll.description)
        .bind(expiration)
        .execute(&mut *tx)
        .await
    {
        eprintln!("Failed to create poll: {}", e);
        return (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to create poll"
        ).into_response();
    };

    let mut query = QueryBuilder::new("INSERT INTO options(poll_token, name)");
    query.push_values(options, |mut b, option| {
        b.push_bind(&token).push_bind(option);
    });
    let query = query.build();
    if let Err(e) = query.execute(&mut *tx).await {
        eprintln!("Failed to create poll options: {}", e);
        return (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to create poll",
        )
            .into_response();
    }

    if let Err(e) = tx.commit().await {
        eprintln!("Failed to create poll options: {}", e);
        return (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to create poll",
        )
            .into_response();
    }

    let mut response = Redirect::to(&format!("/poll/{}/view", token)).into_response();
    response.headers_mut().append(
        "Set-Cookie",
        format!(
            "admin_{}={}; Secure; HttpOnly; Max-Age={}",
            token,
            admin_token,
            Duration::days(90).whole_seconds()
        )
        .parse()
        .expect("admin token cookie generation"),
    );
    response
}

async fn new_poll_new_option(State(state): State<AppState>) -> impl IntoResponse {
    Html(
        state
            .render(
                "new_poll_new_option.html",
                context! {option => None::<String>},
            )
            .unwrap(),
    )
}

async fn new_poll_del_option(State(state): State<AppState>) -> impl IntoResponse {
    Html(
        state
            .render("new_poll_del_option.html", context! {})
            .unwrap(),
    )
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Board {
    by_voters: BTreeMap<String, Votes>,
    options: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Votes {
    edit_token: Token,
    id: u64,
    votes: Vec<Vote>,
}

type Vote = i8;

fn score_class(vote: &f32) -> &'static str {
    match vote {
        -2f32..=0f32 => "good",
        -7f32..=-2f32 => "medium",
        -10f32..=-7f32 => "bad",
        _ => "error",
    }
}

#[derive(Debug, Serialize)]
struct RenderableBoard<'a> {
    voter_names: Vec<&'a str>,
    option_names: Vec<&'a str>,
    by_options: Vec<Vec<Vote>>,
    by_voters: Vec<Vec<Vote>>,
    can_edit_by_voters: Vec<bool>,
    sum_by_options: Vec<i64>,
    score_by_options: Vec<f32>,
    score_class_by_options: Vec<&'a str>,
    change_vote_url: String,
}

impl<'a> RenderableBoard<'a> {
    fn from(
        src: &'a Board,
        poll_token: &Token,
        is_admin: bool,
        edit_token: Option<&str>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let change_vote_url = format!("/poll/{}/vote", poll_token);

        let option_names: Vec<_> = src.options.iter().map(|s| s.as_str()).collect();
        let num_options = option_names.len();
        let voter_names: Vec<_> = src.by_voters.keys().map(|s| s.as_str()).collect();
        let num_voters = voter_names.len();

        let mut by_voters = vec![];
        let mut can_edit_by_voters = vec![];
        for (voter, votes) in &src.by_voters {
            if votes.votes.len() != num_options {
                return Err(format!(
                    "{}: wrong number of votes: has {}, wants {}",
                    voter,
                    votes.votes.len(),
                    num_options
                )
                .into());
            }
            by_voters.push(votes.votes.clone());
            can_edit_by_voters.push(is_admin || edit_token == Some(&votes.edit_token));
        }

        let by_options: Vec<Vec<_>> = (0..num_options)
            .map(|i| {
                src.by_voters
                    .values()
                    // bounds already checked while iterating over by_voters
                    .map(|v| v.votes[i].to_owned())
                    .collect()
            })
            .collect();

        let sum_by_options: Vec<_> = by_options
            .iter()
            .map(|o| o.iter().fold(0i64, |a, i| a + (*i as i64)))
            .collect();
        let mut score_by_options: Vec<_> = sum_by_options
            .iter()
            .map(|s| *s as f32 / num_voters as f32)
            .collect();
        if num_voters == 0 {
            // avoid NaN as average
            score_by_options = sum_by_options.iter().map(|_| 0f32).collect();
        }
        let score_class_by_options = score_by_options.iter().map(score_class).collect();

        Ok(RenderableBoard {
            voter_names,
            option_names,
            by_options,
            by_voters,
            can_edit_by_voters,
            sum_by_options,
            score_by_options,
            score_class_by_options,
            change_vote_url,
        })
    }

    fn disable_votes(&mut self) {
        self.can_edit_by_voters = vec![false; self.voter_names.len()];
    }
}

#[derive(Debug)]
struct Poll {
    title: String,
    admin_token: Token,
    description: String,
    expiration: time::OffsetDateTime,
    board: Json<Board>,
}

async fn query_poll(db: &SqlitePool, token: &Token) -> Result<Option<Poll>, sqlx::Error> {
    sqlx::query_as!(
        Poll,
        r#"
        SELECT
            title,
            admin_token as "admin_token: Token",
            description,
            expiration as "expiration: time::OffsetDateTime",
            (
                SELECT
                    json_object(
                        'by_voters', (
                            SELECT
                                json_group_object(
                                    voter,
                                    json(obj)
                                )
                            FROM (
                                SELECT
                                    voters.name as voter,
                                    json_object(
                                        'id', voters.id,
                                        'edit_token', voters.edit_token,
                                        'votes', json_group_array(
                                            COALESCE(votes.vote, 0)
                                        )
                                    ) as obj
                                FROM voters
                                    INNER JOIN options
                                        ON voters.poll_token = options.poll_token
                                    LEFT JOIN votes
                                        ON votes.voter_id = voters.id
                                        AND votes.option = options.name
                                WHERE
                                    voters.poll_token == polls.token
                                GROUP BY
                                    voters.name
                                ORDER BY
                                    options.rowid
                            )
                        ),
                        'options', (
                            SELECT json_group_array(name)
                            FROM options
                            WHERE poll_token = polls.token
                            ORDER BY rowid
                        )
                    )
            ) as "board!: Json<Board>"
        FROM polls
        WHERE token = ?
        "#,
        token
    )
    .fetch_optional(db)
    .await
}

async fn view_poll(
    State(state): State<AppState>,
    Path(token): Path<Token>,
    cookies: CookieJar,
) -> Result<Response, Response> {
    match query_poll(&state.db, &token).await {
        Ok(Some(Poll {
            title,
            admin_token,
            description,
            expiration,
            board,
        })) => {
            let is_expired = OffsetDateTime::now_utc() > expiration;

            let edit_cookie_value = cookies.get(&format!("edit_{}", token)).map(|c| c.value());

            let admin_cookie_value = cookies.get(&format!("admin_{}", token)).map(|c| c.value());
            let is_admin = admin_cookie_value == Some(admin_token.as_ref());

            let mut board = match RenderableBoard::from(&board, &token, is_admin, edit_cookie_value)
            {
                Ok(b) => b,
                Err(e) => {
                    eprint!("Error loading board: {}: {:?}", token, e);
                    return Ok((
                        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                        "Error fetching poll",
                    )
                        .into_response());
                }
            };

            if is_expired {
                board.disable_votes();
            }

            let mut context = context! {
                title => &title,
                description => &description,
                expiration => &expiration.format(&Rfc3339).unwrap(),
                token => &token,
                board => &board,
                is_expired => &is_expired,
                is_admin => &is_admin,
            };
            if !is_expired {
                context = context! {
                    new_voter_url => &format!("/poll/{}/new_voter", token),
                    ..context
                };
            }
            if is_admin {
                context = context! {
                    admin_share_url => &format!("/poll/{}/admin/share", token),
                    edit_url => &format!("/poll/{}/admin/edit", token),
                    ..context
                };
            }

            let html = state.render("view_poll.html", context)?;
            Ok(Html(html).into_response())
        }
        // todo: better 404 page
        Ok(None) => Err((axum::http::StatusCode::NOT_FOUND, "Poll not found").into_response()),
        Err(e) => {
            eprintln!("Error fetching poll: {}: {:?}", token, e);
            Err((
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Error fetching poll",
            )
                .into_response())
        }
    }
}

async fn share_admin(
    State(state): State<AppState>,
    Path(token): Path<Token>,
    cookies: CookieJar,
) -> impl IntoResponse {
    let poll = sqlx::query!(
        r#"
        SELECT
            title,
            admin_token
        FROM polls
        WHERE token = ?
        "#,
        token
    )
    .fetch_optional(&state.db)
    .await;

    match poll {
        Ok(Some(poll)) => {
            let is_admin = cookies
                .get(&format!("admin_{}", token))
                .map(|t| t.value() == poll.admin_token)
                .unwrap_or(false);

            let context = context! {
                is_admin => &is_admin,
                admin_url => &format!("/poll/{}/admin/{}", token, poll.admin_token),
            };

            let html = state.render("share_poll.html", context).unwrap();
            Html(html).into_response()
        }
        Ok(None) => (axum::http::StatusCode::NOT_FOUND, "Poll not found").into_response(),
        Err(e) => {
            eprintln!("Error fetching poll: {}: {:?}", token, e);
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Error fetching poll",
            )
                .into_response()
        }
    }
}

async fn edit_poll(
    State(state): State<AppState>,
    Path(token): Path<Token>,
    cookies: CookieJar,
) -> impl IntoResponse {
    view_poll(State(state), Path(token), cookies).await
}

async fn login_admin(
    State(state): State<AppState>,
    Path((token, admin_token)): Path<(Token, Token)>,
    cookies: CookieJar,
) -> impl IntoResponse {
    let poll = sqlx::query!(
        r#"
        SELECT
            token as "token!: Token",
            admin_token as "admin_token!: Token",
            expiration as "expiration: time::OffsetDateTime"
        FROM polls
        WHERE
            token = ?
        "#,
        token
    )
    .fetch_optional(&state.db)
    .await;

    match poll {
        Ok(Some(poll)) => {
            if poll.admin_token == admin_token {
                let cookies = cookies.add(make_admin_cookie(
                    &poll.token,
                    &poll.admin_token,
                    poll.expiration,
                ));
                (cookies, Redirect::to(&format!("/poll/{}/view", token))).into_response()
            } else {
                (axum::http::StatusCode::FORBIDDEN, "Wrong Admin Token").into_response()
            }
        }
        Ok(None) => (axum::http::StatusCode::NOT_FOUND, "Poll not found").into_response(),
        Err(e) => {
            eprintln!("Error fetching poll: {}: {:?}", token, e);
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Error fetching poll",
            )
                .into_response()
        }
    }
}

#[derive(Deserialize)]
struct NewVoterForm {
    name: String,
}

async fn new_voter(
    State(state): State<AppState>,
    Path(token): Path<Token>,
    cookies: CookieJar,
    Form(new_voter): Form<NewVoterForm>,
) -> impl IntoResponse {
    let defaults = context! {new_voter_url => &format!("/poll/{}/new_voter", token)};

    let poll = match sqlx::query!(
        r#"
            SELECT
                polls.expiration AS "expiration!: time::OffsetDateTime",
                json_group_array(voters.name)
                    FILTER (WHERE voters.name IS NOT NULL)
                    AS "voters!: Json<Vec<String>>"
            FROM
                polls
                LEFT JOIN voters ON voters.poll_token = polls.token
            WHERE
                token = ?
        "#,
        token,
    )
    .fetch_optional(&state.db)
    .await
    {
        Ok(Some(p)) => p,
        Ok(None) => {
            let html = state
                .render(
                    "frag-new-voter-form.html",
                    context! {
                        error => "poll not found",
                        error_fixable => &false,
                        ..defaults,
                    },
                )
                .unwrap();
            return (axum::http::StatusCode::NOT_FOUND, Html(html)).into_response();
        }
        Err(e) => {
            eprintln!("Error fetching poll: {}: {:?}", token, e);
            return (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Error fetching poll",
            )
                .into_response();
        }
    };
    let is_expired = OffsetDateTime::now_utc() > poll.expiration;
    if is_expired {
        let html = state
            .render(
                "frag-new-voter-form.html",
                context! {
                    error => "the poll has expired",
                    error_fixable => &false,
                    ..defaults,
                },
            )
            .unwrap();
        return (axum::http::StatusCode::GONE, Html(html)).into_response();
    }

    let name = new_voter.name.trim().to_string();
    if name.is_empty() {
        let html = state
            .render(
                "frag-new-voter-form.html",
                context! {
                    error => "you have to provide a name",
                    error_fixable => &true,
                    ..defaults,
                },
            )
            .unwrap();
        return (axum::http::StatusCode::BAD_REQUEST, Html(html)).into_response();
    }
    // todo: lowercase names for comparison
    if poll.voters.contains(&name) {
        let html = state
            .render(
                "frag-new-voter-form.html",
                context! {
                    error => "name already in use",
                    error_fixable => &true,
                    voter_name => &name,
                    ..defaults,
                },
            )
            .unwrap();
        return (axum::http::StatusCode::BAD_REQUEST, Html(html)).into_response();
    }

    let mut edit_token = Token::new();

    if let Some(edit_cookie) = cookies.get(&format!("edit_{}", &token)) {
        edit_token = match edit_cookie.value().parse() {
            Ok(t) => t,
            Err(e) => {
                eprintln!(
                    "Invalid editor token while adding new voter: {}: {:?}",
                    token, e
                );
                return (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    "Invalid editor token",
                )
                    .into_response();
            }
        }
    }

    if let Err(e) = sqlx::query!(
        r#"
            INSERT INTO
                voters(name, poll_token, edit_token)
            VALUES
                (?, ?, ?)
        "#,
        name,
        token,
        edit_token,
    )
    .execute(&state.db)
    .await
    {
        eprintln!("Error adding new voter: {}: {:?}", token, e);
        return (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "Error adding new voter",
        )
            .into_response();
    }

    let cookies = cookies.add(make_edit_token(&token, &edit_token, poll.expiration));
    (cookies, HxRefresh(true), "voter added").into_response()
}

#[derive(Deserialize, Debug)]
struct VoteForm {
    voter: String,
    option: String,
    vote: Vote,
}

async fn vote(
    State(state): State<AppState>,
    Path(token): Path<Token>,
    cookies: CookieJar,
    Form(vote): Form<VoteForm>,
) -> Result<Response, Response> {
    let q = match sqlx::query!(
        r#"
            SELECT
                unixepoch(polls.expiration, 'utc') < unixepoch('now', 'utc') as "is_expired!: bool",
                polls.admin_token as "admin_token!: Token",
                json_group_object(voters.name, voters.edit_token)
                    FILTER (WHERE voters.name IS NOT NULL)
                    as "voters!: Json<BTreeMap<String, Token>>"
            FROM
                polls
                LEFT JOIN voters ON voters.poll_token = polls.token
            WHERE
                polls.token = ?
            GROUP BY
                polls.rowid
        "#,
        token,
    )
    .fetch_optional(&state.db)
    .await
    {
        Ok(Some(q)) => q,
        Ok(None) => {
            return Err((axum::http::StatusCode::NOT_FOUND, "Poll not found").into_response());
        }
        Err(e) => {
            eprintln!("Error fetching poll: {}: {:?}", token, e);
            return Err((
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Error fetching poll",
            )
                .into_response());
        }
    };

    eprintln!("{:?}", q);

    let edit_cookie_value = cookies.get(&format!("edit_{}", token)).map(|c| c.value());
    let admin_cookie_value = cookies.get(&format!("admin_{}", token)).map(|c| c.value());
    let is_admin = admin_cookie_value == Some(q.admin_token.as_ref());

    if q.is_expired {
        return Ok((axum_htmx::HxRefresh(true), "Poll has expired").into_response());
    }

    let Some(edit_token) = q.voters.get(&vote.voter) else {
        eprintln!("Voter not in poll: {}: '{}'", token, vote.voter);
        return Err((axum::http::StatusCode::BAD_REQUEST, "Voter not found").into_response());
    };
    let is_voter = edit_cookie_value == Some(edit_token.as_ref());
    if !(is_voter || is_admin) {
        eprintln!("Error registering vote: {}: neither admin nor voter", token);
        return Err((
            axum::http::StatusCode::FORBIDDEN,
            "Forbidden: neither admin nor voter",
        )
            .into_response());
    }

    // everything is verified, now upsert the vote
    match sqlx::query!(
        r#"
            INSERT INTO votes (voter_id, option, poll_token, vote)
            VALUES (
                (SELECT id FROM voters WHERE poll_token = ? AND name = ?),
                ?,
                ?,
                ?
            )
            ON CONFLICT (voter_id, option) DO UPDATE SET vote = excluded.vote
        "#,
        token,
        vote.voter,
        vote.option,
        token,
        vote.vote
    )
    .execute(&state.db)
    .await
    {
        Ok(_) => {
            eprintln!("Did it!");
        }
        Err(e) => {
            eprintln!("Error upserting vote: {}: {:?}", token, e);
            return Err((
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Error registering vote",
            )
                .into_response());
        }
    }

    let poll = match query_poll(&state.db, &token).await {
        Ok(Some(poll)) => poll,
        Ok(None) => {
            return Err((axum::http::StatusCode::NOT_FOUND, "Poll not found").into_response());
        }
        Err(e) => {
            eprintln!("Error fetching poll: {}: {:?}", token, e);
            return Err((
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Error fetching poll",
            )
                .into_response());
        }
    };

    let mut board = match RenderableBoard::from(&poll.board, &token, is_admin, edit_cookie_value) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Error loading board: {}: {:?}", token, e);
            return Err((
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Error fetching poll",
            )
                .into_response());
        }
    };

    if OffsetDateTime::now_utc() > poll.expiration {
        board.disable_votes();
    }

    Ok(Html(state.render("frag-board.html", context! { board })?).into_response())
}

fn make_admin_cookie(poll: &Token, admin: &Token, expiration: OffsetDateTime) -> Cookie<'static> {
    Cookie::build((format!("admin_{}", poll), admin.to_string()))
        .secure(true)
        .http_only(true)
        .same_site(axum_extra::extract::cookie::SameSite::Lax)
        .max_age(expiration - OffsetDateTime::now_utc())
        .path(format!("/poll/{}/", poll))
        .into()
}

fn make_edit_token(poll: &Token, edit: &Token, expiration: OffsetDateTime) -> Cookie<'static> {
    Cookie::build((format!("edit_{}", poll), edit.to_string()))
        .secure(true)
        .http_only(true)
        .same_site(axum_extra::extract::cookie::SameSite::Lax)
        .max_age(expiration - OffsetDateTime::now_utc())
        .path(format!("/poll/{}/", poll))
        .into()
}
