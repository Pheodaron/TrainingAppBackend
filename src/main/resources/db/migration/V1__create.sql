CREATE TABLE users (
    id SERIAL NOT NULL PRIMARY KEY,
    username VARCHAR(100) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL UNIQUE,
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    password VARCHAR(255) NOT NULL,
    created TIMESTAMP DEFAULT current_timestamp NOT NULL,
    updated TIMESTAMP DEFAULT current_timestamp NOT NULL,
    status VARCHAR(25) DEFAULT 'ACTIVE' NOT NULL
);

CREATE TABLE roles (
        id SERIAL NOT NULL PRIMARY KEY,
        name VARCHAR(100) NOT NULL UNIQUE,
        created TIMESTAMP DEFAULT current_timestamp NOT NULL,
        updated TIMESTAMP DEFAULT current_timestamp NOT NULL,
        status VARCHAR(25) DEFAULT 'ACTIVE' NOT NULL
);

CREATE TABLE user_roles (
    user_id BIGINT,
    role_id BIGINT,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE ON UPDATE RESTRICT,
    FOREIGN KEY (role_id) REFERENCES roles (id) ON DELETE CASCADE ON UPDATE RESTRICT
);