use axum::{
    extract::{Path, State}, http::header, response::{IntoResponse, Redirect}, routing::{get, post}, Router
};
use axum_extra::{extract::{cookie::Cookie, CookieJar, Form}, response::Html};
use axum_htmx::{AutoVaryLayer, HxRefresh};
use serde::{Deserialize, Serialize};
use clap::Parser;
use time::{format_description::well_known::Rfc3339, Duration, OffsetDateTime};
use std::{collections::BTreeMap, net::SocketAddr, path::PathBuf, str::FromStr};
use tokio;
use tera::{Context, Tera};
use sqlx::{migrate::MigrateError, sqlite::{SqliteConnectOptions, SqlitePool}, QueryBuilder, types::Json};
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
    tera: Tera,
    db: SqlitePool,
}

async fn migrate(pool: &SqlitePool) -> Result<(), MigrateError> {
    sqlx::migrate!("./migrations/").run(pool).await
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
    let tera = match Tera::new("templates/**/*") {
        Ok(t) => t,
        Err(e) => {
            println!("Parsing error(s): {}", e);
            ::std::process::exit(1);
        }
    };

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
        .with_state(AppState{tera, db: pool});

    println!("Listening on {}", args.bind);

    // Start the server
    let listener = tokio::net::TcpListener::bind(&args.bind).await.unwrap();
    axum::serve(listener, app).await.unwrap();

    Ok(())
}

async fn index(State(state): State<AppState>) -> impl IntoResponse {
    let mut context = tera::Context::new();
    context.insert("title", "Simple Axum Server");
    context.insert("heading", "Welcome to the Simple Axum Server");
    context.insert("message", "This page is rendered using Tera templates with Pico.css and HTMX.");

    let html = state.tera.render("index.html", &context).unwrap();

    (
        [(header::CONTENT_TYPE, "text/html"), (header::CACHE_CONTROL, "no-cache")],
        Html(html)
    )
}

async fn new_poll_form(State(state): State<AppState>) -> impl IntoResponse {
    let mut context = tera::Context::new();
    context.insert("title", "Create New Poll");
    context.insert("options", &vec!(None::<String>, None, None));

    let html = state.tera.render("new_poll.html", &context).unwrap();

    (
        [(header::CONTENT_TYPE, "text/html"), (header::CACHE_CONTROL, "no-cache")],
        Html(html)
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
    let options: Vec<_> = new_poll.options.iter()
        .map(|s| s.trim())
        .filter(|s| s.len() > 0)
        .collect();

    if options.len() > MAX_OPTIONS {
        eprintln!("Failed to create poll: too many options: {}", options.len());
        return (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to create poll"
        ).into_response();
    }

    let Ok(mut tx) = state.db.begin().await else {
        eprintln!("Failed to create poll: transaction error");
        return (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to create poll"
        ).into_response();
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

    let mut query = QueryBuilder::new("INSERT INTO options(poll_token, name)" );
    query.push_values(
        options,
        |mut b, option| { b.push_bind(&token).push_bind(option); }
    );
    let query = query.build();
    if let Err(e) = query.execute(&mut *tx).await {
        eprintln!("Failed to create poll options: {}", e);
        return (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to create poll"
        ).into_response();
    }

    if let Err(e) = tx.commit().await {
        eprintln!("Failed to create poll options: {}", e);
        return (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to create poll"
        ).into_response();
    }

    let mut response = Redirect::to(&format!("/poll/{}/view", token)).into_response();
    response.headers_mut().append(
        "Set-Cookie",
        format!(
            "admin_{}={}; Secure; HttpOnly; Max-Age={}",
            token,
            admin_token,
            Duration::days(90).whole_seconds()
        ).parse().expect("admin token cookie generation")
    );
    response
}

async fn new_poll_new_option(State(state): State<AppState>) -> impl IntoResponse {
    let mut context = Context::new();
    context.insert("option", &None::<String>);
    Html(state.tera.render("new_poll_new_option.html", &context).unwrap())
}

async fn new_poll_del_option(State(state): State<AppState>) -> impl IntoResponse {
    Html(state.tera.render("new_poll_del_option.html", &Context::default()).unwrap())
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

#[derive(Debug, Serialize, Default)]
struct RenderableBoard<'a> {
    voter_names: Vec<&'a str>,
    option_names: Vec<&'a str>,
    by_options: Vec<Vec<Vote>>,
    by_voters: Vec<Vec<Vote>>,
    can_edit_by_voters: Vec<bool>,
    score_by_options: Vec<i64>,
    change_vote_url: String,
}

impl<'a> RenderableBoard<'a> {
    fn from(
        src: &'a Board,
        poll_token: &Token,
        is_admin: bool,
        edit_token: Option<&str>
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let mut dst = Self::default();
        dst.change_vote_url = format!("/poll/{}/vote", poll_token);

        dst.option_names = src.options.iter()
            .map(|s| s.as_str())
            .collect();
        let num_options = dst.option_names.len();
        dst.voter_names = src.by_voters.keys()
            .map(|s| s.as_str())
            .collect();

        for (voter, votes) in &src.by_voters {
            if votes.votes.len() != num_options {
                return Err(
                    format!(
                        "{}: wrong number of votes: has {}, wants {}",
                        voter,
                        votes.votes.len(),
                        num_options
                    ).into()
                );
            }
            dst.by_voters.push(votes.votes.clone());
            dst.can_edit_by_voters.push(is_admin || edit_token == Some(&votes.edit_token));
        }

        dst.by_options = (0..num_options)
            .map(
                |i|
                {
                    src.by_voters
                        .values()
                        // bounds already checked while iterating over by_voters
                        .map(|v| v.votes[i].to_owned())
                        .collect()
                }
            )
            .collect();

        dst.score_by_options = dst.by_options
            .iter()
            .map(|o| o.iter().fold(0i64, |a, i| a + (*i as i64)))
            .collect();

        Ok(dst)
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
) -> impl IntoResponse {
    match query_poll(&state.db, &token).await {
        Ok(Some(Poll { title, admin_token, description, expiration, board })) => {
            let is_expired = OffsetDateTime::now_utc() > expiration;

            let edit_cookie_value = cookies
                .get(&format!("edit_{}", token))
                .map(|c| c.value());

            let admin_cookie_value = cookies
                .get(&format!("admin_{}", token))
                .map(|c| c.value());
            let is_admin = admin_cookie_value == Some(&admin_token.to_string());

            let board = match RenderableBoard::from(&board, &token, is_admin, edit_cookie_value) {
                Ok(b) => b,
                Err(e) => {
                    eprint!("Error loading board: {}: {:?}", token, e);
                    return (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "Error fetching poll").into_response();
                },
            };

            let mut context = tera::Context::new();
            context.insert("title", &title);
            context.insert("description", &description);
            context.insert("expiration", &expiration.format(&Rfc3339).unwrap());
            context.insert("token", &token);
            context.insert("board", &board);
            context.insert("is_expired", &is_expired);
            context.insert("is_admin", &is_admin);
            if !is_expired {
                context.insert("new_voter_url", &format!("/poll/{}/new_voter", token));
            }
            if is_admin {
                context.insert("admin_share_url", &format!("/poll/{}/admin/share", token));
                context.insert("edit_url", &format!("/poll/{}/admin/edit", token));
            }

            let html = state.tera.render("view_poll.html", &context).unwrap();
            Html(html).into_response()
        },
        Ok(None) => (axum::http::StatusCode::NOT_FOUND, "Poll not found").into_response(),
        Err(e) => {
            eprintln!("Error fetching poll: {}: {:?}", token, e);
            (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "Error fetching poll").into_response()
        },
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

            let mut context = tera::Context::new();
            context.insert("is_admin", &is_admin);
            context.insert("admin_url", &format!("/poll/{}/admin/{}", token, poll.admin_token));

            let html = state.tera.render("share_poll.html", &context).unwrap();
            Html(html).into_response()
        },
        Ok(None) => (axum::http::StatusCode::NOT_FOUND, "Poll not found").into_response(),
        Err(e) => {
            eprintln!("Error fetching poll: {}: {:?}", token, e);
            (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "Error fetching poll").into_response()
        },
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
                let cookies = cookies.add(make_admin_cookie(&poll.token, &poll.admin_token, poll.expiration));
                (cookies, Redirect::to(&format!("/poll/{}/view", token))).into_response()
            } else {
                (axum::http::StatusCode::FORBIDDEN, "Wrong Admin Token").into_response()
            }
        },
        Ok(None) => (axum::http::StatusCode::NOT_FOUND, "Poll not found").into_response(),
        Err(e) => {
            eprintln!("Error fetching poll: {}: {:?}", token, e);
            (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "Error fetching poll").into_response()
        },
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
    let mut context = Context::new();
    context.insert("new_voter_url", &format!("/poll/{}/new_voter", token));

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
    ).fetch_optional(&state.db).await {
        Ok(Some(p)) => p,
        Ok(None) => {
            context.insert("error", "poll not found");
            context.insert("error_fixable", &false);

            let html = state.tera.render("frag-new-voter-form.html", &context).unwrap();
            return (axum::http::StatusCode::NOT_FOUND, Html(html)).into_response();
        },
        Err(e) => {
            eprintln!("Error fetching poll: {}: {:?}", token, e);
            return (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "Error fetching poll").into_response();
        },
    };
    let is_expired = OffsetDateTime::now_utc() > poll.expiration;
    if is_expired {
        context.insert("error", "the poll has expired");
        context.insert("error_fixable", &false);

        let html = state.tera.render("frag-new-voter-form.html", &context).unwrap();
        return (axum::http::StatusCode::GONE, Html(html)).into_response();
    }

    let name = new_voter.name.trim().to_string();
    if name.is_empty() {
        context.insert("error", "you have to provide a name");
        context.insert("error_fixable", &true);

        let html = state.tera.render("frag-new-voter-form.html", &context).unwrap();
        return (axum::http::StatusCode::BAD_REQUEST, Html(html)).into_response();
    }
    // todo: lowercase names for comparison
    if poll.voters.contains(&name) {
        context.insert("error", "name already in use");
        context.insert("error_fixable", &true);
        context.insert("voter_name", &name);

        let html = state.tera.render("frag-new-voter-form.html", &context).unwrap();
        return (axum::http::StatusCode::BAD_REQUEST, Html(html)).into_response();
    }

    let mut edit_token = Token::new();

    if let Some(edit_cookie) = cookies.get(&format!("edit_{}", &token)) {
        edit_token = match edit_cookie.value().parse() {
            Ok(t) => t,
            Err(e) => {
                eprintln!("Invalid editor token while adding new voter: {}: {:?}", token, e);
                return (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "Invalid editor token").into_response();
            },
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
    ).execute(&state.db).await {
        eprintln!("Error adding new voter: {}: {:?}", token, e);
        return (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "Error adding new voter").into_response();
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
) -> impl IntoResponse {
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
    ).fetch_optional(&state.db).await {
        Ok(Some(q)) => q,
        Ok(None) => { return (axum::http::StatusCode::NOT_FOUND, "Poll not found").into_response(); },
        Err(e) => {
            eprintln!("Error fetching poll: {}: {:?}", token, e);
            return (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "Error fetching poll").into_response();
        },
    };

    eprintln!("{:?}", q);

    let edit_cookie_value = cookies
        .get(&format!("edit_{}", token))
        .map(|c| c.value());
    let admin_cookie_value = cookies
        .get(&format!("admin_{}", token))
        .map(|c| c.value());
    let is_admin = admin_cookie_value == Some(&q.admin_token.to_string());

    if !q.is_expired {
        let Some(edit_token) = q.voters.get(&vote.voter) else {
            eprintln!("Voter not in poll: {}: '{}'", token, vote.voter);
            return (axum::http::StatusCode::BAD_REQUEST, "Voter not found").into_response();
        };
        let is_voter = edit_cookie_value == Some(&edit_token.to_string());
        if !(is_voter || is_admin) {
            eprintln!("Error registering vote: {}: neither admin nor voter", token);
            return (axum::http::StatusCode::FORBIDDEN, "Forbidden: neither admin nor voter").into_response();
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
        ).execute(&state.db).await {
            Ok(_) => { eprintln!("Did it!"); },
            Err(e) => {
                eprintln!("Error upserting vote: {}: {:?}", token, e);
                return (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "Error registering vote").into_response();
            }
        }
    }

    let poll = match query_poll(&state.db, &token).await {
        Ok(Some(poll)) => poll,
        Ok(None) => { return (axum::http::StatusCode::NOT_FOUND, "Poll not found").into_response(); },
        Err(e) => {
            eprintln!("Error fetching poll: {}: {:?}", token, e);
            return (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "Error fetching poll").into_response();
        },
    };

    let board = match RenderableBoard::from(&poll.board, &token, is_admin, edit_cookie_value) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Error loading board: {}: {:?}", token, e);
            return (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "Error fetching poll").into_response();
        },
    };

    let mut context = tera::Context::new();
    context.insert("board", &board);

    match state.tera.render("frag-board.html", &context) {
        Ok(html) => Html(html).into_response(),
        Err(e) => {
            eprintln!("Template rendering error: {:?}", e);
            (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "Error rendering template").into_response()
        }
    }
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
