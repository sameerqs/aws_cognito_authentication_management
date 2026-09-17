-- Reference schema for the authentication system.
-- Generated from app/models.py. The application also creates these
-- tables at startup via create_all(), so this file is documentation
-- and a starting point for a real migration, not a required step.
--
-- Deliberately absent: any column holding an access token, and any
-- column holding a refresh or magic-link token in readable form.

CREATE TABLE users (
	id UUID NOT NULL, 
	cognito_sub VARCHAR(64) NOT NULL, 
	email VARCHAR(320) NOT NULL, 
	age INTEGER, 
	status VARCHAR(32) NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, 
	updated_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, 
	PRIMARY KEY (id), 
	CONSTRAINT ck_users_status CHECK (status IN ('onboarding_pending', 'active', 'disabled')), 
	CONSTRAINT ck_users_age_range CHECK (age IS NULL OR (age >= 13 AND age <= 120))
);
CREATE UNIQUE INDEX ix_users_cognito_sub ON users (cognito_sub);
CREATE UNIQUE INDEX ix_users_email ON users (email);

CREATE TABLE user_sessions (
	id UUID NOT NULL, 
	user_id UUID NOT NULL, 
	refresh_token_hash VARCHAR(64) NOT NULL, 
	access_token_expires_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	refresh_token_expires_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, 
	last_used_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, 
	revoked_at TIMESTAMP WITH TIME ZONE, 
	user_agent VARCHAR(512), 
	ip_address VARCHAR(45), 
	PRIMARY KEY (id), 
	FOREIGN KEY(user_id) REFERENCES users (id) ON DELETE CASCADE
);
CREATE INDEX ix_user_sessions_refresh_token_hash ON user_sessions (refresh_token_hash);
CREATE INDEX ix_user_sessions_user_id ON user_sessions (user_id);
CREATE INDEX ix_user_sessions_user_revoked ON user_sessions (user_id, revoked_at);

CREATE TABLE login_requests (
	id UUID NOT NULL, 
	email VARCHAR(320) NOT NULL, 
	cognito_session TEXT NOT NULL, 
	token_hash VARCHAR(64) NOT NULL, 
	expires_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	consumed_at TIMESTAMP WITH TIME ZONE, 
	created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, 
	PRIMARY KEY (id)
);
CREATE INDEX ix_login_requests_email ON login_requests (email);

