CREATE TABLE refreshtokens (
    id SERIAL NOT NULL PRIMARY KEY,
    user_id INTEGER NOT NULL UNIQUE,
    token VARCHAR(255) NOT NULL UNIQUE,
    expiry_date TIMESTAMP NOT NULL
);