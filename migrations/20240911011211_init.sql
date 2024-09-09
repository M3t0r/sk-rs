CREATE TABLE IF NOT EXISTS polls (
    token TEXT PRIMARY KEY,
    admin_token TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    expiration TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS options (
    id INTEGER PRIMARY KEY,
    poll_token TEXT NOT NULL,
    name TEXT NOT NULL,
    UNIQUE(poll_token, name),
    FOREIGN KEY(poll_token)
        REFERENCES polls(token)
        ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS voters (
    id INTEGER PRIMARY KEY,
    edit_token TEXT NOT NULL,
    poll_token TEXT NOT NULL,
    name TEXT NOT NULL,
    UNIQUE(poll_token, name),
    FOREIGN KEY(poll_token)
        REFERENCES polls(token)
        ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS votes (
    voter_id INTEGER NOT NULL,
    option TEXT NOT NULL,
    poll_token TEXT NOT NULL,
    vote INTEGER NOT NULL CHECK (
        vote BETWEEN -10 AND 0
        AND CAST(vote AS INTEGER) == vote
    ),
    UNIQUE(voter_id, option),
    FOREIGN KEY(voter_id)
        REFERENCES voters(id)
        ON DELETE CASCADE,
    FOREIGN KEY(poll_token)
        REFERENCES polls(token)
        ON DELETE CASCADE,
    FOREIGN KEY(option, poll_token)
        REFERENCES options(name, poll_token)
        ON DELETE CASCADE
);
