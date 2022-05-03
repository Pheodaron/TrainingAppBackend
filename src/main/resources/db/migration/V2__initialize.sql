INSERT INTO roles (name) VALUES
    ('ROLE_USER'),
    ('ROLE_ADMIN');

INSERT INTO users (id, username, email, first_name, last_name, password)
VALUES (1, 'Admin', 'Admin@mail.ru', 'Admin', 'Admin', '$2a$12$.jodYCFID3OOisvp3DYH0.DqgVAmi9d1QfPcQdeHJWvNMambQGeQS');

INSERT INTO user_roles (user_id, role_id) VALUES
    (1, 1),
    (1, 2);