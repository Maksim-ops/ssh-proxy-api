CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(128) NOT NULL UNIQUE,
  email VARCHAR(255) NOT NULL UNIQUE,
  role VARCHAR(32) NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_login TIMESTAMP NULL DEFAULT NULL,
  public_key TEXT NULL
);

CREATE TABLE IF NOT EXISTS proxies (
  id INT AUTO_INCREMENT PRIMARY KEY,
  proxy VARCHAR(255) NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS servers (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(128) NOT NULL UNIQUE,
  host VARCHAR(255) NOT NULL,
  ip VARCHAR(64) NULL,
  proxy_id INT NULL,
  port INT NOT NULL DEFAULT 22,
  environment VARCHAR(64) NOT NULL DEFAULT 'dev',
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_servers_proxy FOREIGN KEY (proxy_id) REFERENCES proxies(id)
);

CREATE TABLE IF NOT EXISTS jobs (
  id INT AUTO_INCREMENT PRIMARY KEY,
  request_id VARCHAR(64) NOT NULL UNIQUE,
  user_id INT NULL,
  server_id INT NULL,
  server_name VARCHAR(128) NOT NULL,
  client_type VARCHAR(16) NOT NULL,
  command TEXT NOT NULL,
  status VARCHAR(16) NOT NULL,
  stdout_lines INT NOT NULL DEFAULT 0,
  stderr_lines INT NOT NULL DEFAULT 0,
  started_at TIMESTAMP NULL DEFAULT NULL,
  finished_at TIMESTAMP NULL DEFAULT NULL,
  exit_code INT NULL,
  CONSTRAINT fk_jobs_user FOREIGN KEY (user_id) REFERENCES users(id),
  CONSTRAINT fk_jobs_server FOREIGN KEY (server_id) REFERENCES servers(id)
);

CREATE TABLE IF NOT EXISTS actions (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(64) NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS audit_events (
  id INT AUTO_INCREMENT PRIMARY KEY,
  request_id VARCHAR(64) NULL,
  user_id INT NULL,
  server_id INT NULL,
  action_id INT NULL,
  resource VARCHAR(255) NOT NULL,
  result VARCHAR(64) NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_audit_user FOREIGN KEY (user_id) REFERENCES users(id),
  CONSTRAINT fk_audit_server FOREIGN KEY (server_id) REFERENCES servers(id),
  CONSTRAINT fk_audit_action FOREIGN KEY (action_id) REFERENCES actions(id)
);

CREATE TABLE IF NOT EXISTS job_logs (
  id INT AUTO_INCREMENT PRIMARY KEY,
  job_id INT NOT NULL,
  log_file VARCHAR(1024) NOT NULL,
  size_bytes INT NOT NULL DEFAULT 0,
  line_count INT NOT NULL DEFAULT 0,
  CONSTRAINT fk_job_logs_job FOREIGN KEY (job_id) REFERENCES jobs(id)
);

CREATE TABLE IF NOT EXISTS command_streams (
  id INT AUTO_INCREMENT PRIMARY KEY,
  job_id INT NOT NULL,
  share_token VARCHAR(128) NOT NULL UNIQUE,
  is_public BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_at TIMESTAMP NULL DEFAULT NULL,
  CONSTRAINT fk_command_streams_job FOREIGN KEY (job_id) REFERENCES jobs(id)
);

CREATE TABLE IF NOT EXISTS tokens (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(128) NOT NULL UNIQUE,
  token_hash VARCHAR(255) NOT NULL,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT IGNORE INTO actions (id, name) VALUES
  (1, 'EXEC_ALLOWED'),
  (2, 'EXEC_DENIED'),
  (3, 'LOGIN'),
  (4, 'CANCEL');

INSERT IGNORE INTO proxies (id, proxy) VALUES
  (1, 'direct');

INSERT IGNORE INTO users (id, username, email, role, public_key) VALUES
  (1, 'maksim.nikitin', 'maksim.nikitin@flant.com', 'admin', NULL);

INSERT IGNORE INTO servers (id, name, host, ip, proxy_id, port, environment, enabled) VALUES
  (1, 'lifeorient', 'lifeorient', '84.54.28.170', 1, 22, 'dev', TRUE);

INSERT IGNORE INTO tokens (id, name, token_hash, enabled) VALUES
  (1, 'default-api-token', SHA2('dev-local-token-change-me', 256), TRUE);

SELECT id, name, host, ip, enabled FROM servers ORDER BY id;
SELECT id, request_id, server_name, status, exit_code FROM jobs ORDER BY id DESC LIMIT 20;
SELECT id, request_id, resource, result, created_at FROM audit_events ORDER BY id DESC LIMIT 20;
