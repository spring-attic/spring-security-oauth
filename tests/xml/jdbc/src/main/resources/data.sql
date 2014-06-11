insert into oauth_client_details (client_id, resource_ids, scope, authorized_grant_types, authorities, access_token_validity) 
	values ('my-trusted-client', 'oauth2-resource', 'read,write,trust', 'password,authorization_code,refresh_token,implicit', 'ROLE_CLIENT,ROLE_TRUSTED_CLIENT', 60);

insert into oauth_client_details (client_id, resource_ids, scope, authorized_grant_types, authorities, web_server_redirect_uri) 
	values ('my-client-with-registered-redirect', 'oauth2-resource', 'read,trust', 'authorization_code', 'ROLE_CLIENT', 'http://anywhere?key=value');

insert into oauth_client_details (client_id, client_secret, resource_ids, scope, authorized_grant_types, authorities) 
	values ('my-client-with-secret', 'secret', 'oauth2-resource', 'read', 'password,client_credentials', 'ROLE_CLIENT');
