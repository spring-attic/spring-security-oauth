create table users (
  username varchar(256),
  password varchar(256),
  enabled boolean
);

create table authorities (
  username varchar(256),
  authority varchar(256)
);

create table oauth_client_details (
  client_id VARCHAR(256) PRIMARY KEY,
  resource_ids VARCHAR(256),
  client_secret VARCHAR(256),
  scope VARCHAR(256),
  authorized_grant_types VARCHAR(256),
  web_server_redirect_uri VARCHAR(256),
  authorities VARCHAR(256),
  access_token_validity INTEGER,
  refresh_token_validity INTEGER,
  additional_information VARCHAR(4096),
  autoapprove VARCHAR(256)
);

create table oauth_client_token (
  token_id VARCHAR(256),
  token LONGVARBINARY,
  authentication_id VARCHAR(256),
  user_name VARCHAR(256),
  client_id VARCHAR(256)
);

create table oauth_access_token (
  token_id VARCHAR(256),
  token LONGVARBINARY,
  authentication_id VARCHAR(256),
  user_name VARCHAR(256),
  client_id VARCHAR(256),
  authentication LONGVARBINARY,
  refresh_token VARCHAR(256)
);

create table oauth_refresh_token (
  token_id VARCHAR(256),
  token LONGVARBINARY,
  authentication LONGVARBINARY
);

create table oauth_code (
  code VARCHAR(256), authentication LONGVARBINARY
);

insert into oauth_client_details (client_id, resource_ids, scope, authorized_grant_types, authorities, access_token_validity) 
	values ('my-trusted-client', 'oauth2-resource', 'read,write,trust', 'password,authorization_code,refresh_token,implicit', 'ROLE_CLIENT,ROLE_TRUSTED_CLIENT', 60);

insert into oauth_client_details (client_id, resource_ids, scope, authorized_grant_types, authorities, web_server_redirect_uri) 
	values ('my-client-with-registered-redirect', 'oauth2-resource', 'read,trust', 'authorization_code', 'ROLE_CLIENT', 'http://anywhere?key=value');

insert into oauth_client_details (client_id, client_secret, resource_ids, scope, authorized_grant_types, authorities) 
	values ('my-client-with-secret', 'secret', 'oauth2-resource', 'read', 'password,client_credentials', 'ROLE_CLIENT');

