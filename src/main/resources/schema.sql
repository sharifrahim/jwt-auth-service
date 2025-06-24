CREATE TABLE IF NOT EXISTS api_client (
    id SERIAL PRIMARY KEY,
    client_id VARCHAR(255) NOT NULL,
    client_secret_enc TEXT NOT NULL,
    private_key_enc TEXT NOT NULL,
    created_by VARCHAR(100),
    created_date TIMESTAMP,
    modify_by VARCHAR(100),
    modify_date TIMESTAMP
);
