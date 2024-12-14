-- DROP SCHEMA public;

CREATE SCHEMA public AUTHORIZATION postgres;

-- DROP SEQUENCE public.auth_user_seq;

CREATE SEQUENCE public.auth_user_seq
	INCREMENT BY 50
	MINVALUE 1
	MAXVALUE 9223372036854775807
	START 1
	CACHE 1
	NO CYCLE;
-- DROP SEQUENCE public.permission_seq;

CREATE SEQUENCE public.permission_seq
	INCREMENT BY 50
	MINVALUE 1
	MAXVALUE 9223372036854775807
	START 1
	CACHE 1
	NO CYCLE;
-- DROP SEQUENCE public.role_seq;

CREATE SEQUENCE public.role_seq
	INCREMENT BY 50
	MINVALUE 1
	MAXVALUE 9223372036854775807
	START 1
	CACHE 1
	NO CYCLE;-- public.auth_user definition

-- Drop table

-- DROP TABLE public.auth_user;

CREATE TABLE public.auth_user (
	id int8 DEFAULT nextval('auth_user_seq'::regclass) NOT NULL,
	account_non_expired bool NULL,
	account_non_locked bool NULL,
	credentials_non_expired bool NULL,
	email varchar(255) NULL,
	enabled bool NULL,
	"password" varchar(255) NULL,
	phone_number varchar(255) NULL,
	user_id varchar(255) NULL,
	username varchar(255) NULL,
	is_kyc_verified bool DEFAULT false NOT NULL,
	CONSTRAINT auth_user_pkey PRIMARY KEY (id),
	CONSTRAINT ukiq1nhlhht0l8mosbw8oomxwcs UNIQUE (user_id),
	CONSTRAINT ukklvc3dss72qnlrjp2bai055mw UNIQUE (email),
	CONSTRAINT ukp78qmr31f74n0y4dfo8t7qm0g UNIQUE (phone_number)
);


-- public.oauth_client_details definition

-- Drop table

-- DROP TABLE public.oauth_client_details;

CREATE TABLE public.oauth_client_details (
	client_id varchar(100) NOT NULL,
	access_token_validity int4 NULL,
	additional_information varchar(255) NULL,
	application_name varchar(255) NULL,
	authorities varchar(255) NULL,
	authorized_grant_types varchar(255) NULL,
	autoapprove varchar(255) NULL,
	client_secret varchar(255) NULL,
	number_user int4 NULL,
	refresh_token_validity int4 NULL,
	resource_ids varchar(255) NULL,
	"scope" varchar(255) NULL,
	username varchar(255) NULL,
	web_server_redirect_uri varchar(255) NULL,
	CONSTRAINT oauth_client_details_pkey PRIMARY KEY (client_id)
);


-- public."permission" definition

-- Drop table

-- DROP TABLE public."permission";

CREATE TABLE public."permission" (
	id int4 DEFAULT nextval('permission_seq'::regclass) NOT NULL,
	"name" varchar(255) NULL,
	CONSTRAINT permission_pkey PRIMARY KEY (id)
);


-- public."role" definition

-- Drop table

-- DROP TABLE public."role";

CREATE TABLE public."role" (
	id int4 DEFAULT nextval('role_seq'::regclass) NOT NULL,
	"name" varchar(255) NULL,
	CONSTRAINT role_pkey PRIMARY KEY (id)
);


-- public.permission_role definition

-- Drop table

-- DROP TABLE public.permission_role;

CREATE TABLE public.permission_role (
	role_id int4 NOT NULL,
	permission_id int4 NOT NULL,
	CONSTRAINT fk3tuvkbyi6wcytyg21hvpd6txw FOREIGN KEY (permission_id) REFERENCES public."permission"(id),
	CONSTRAINT fk50sfdcvbvdaclpn7wp4uop4ml FOREIGN KEY (role_id) REFERENCES public."role"(id)
);


-- public.role_user definition

-- Drop table

-- DROP TABLE public.role_user;

CREATE TABLE public.role_user (
	user_id int8 NOT NULL,
	role_id int4 NOT NULL,
	CONSTRAINT fkiqpmjd2qb4rdkej916ymonic6 FOREIGN KEY (role_id) REFERENCES public."role"(id),
	CONSTRAINT fklb2i1httc6dlloatt4sx3u9l9 FOREIGN KEY (user_id) REFERENCES public.auth_user(id)
);

CREATE TABLE public.authorization_code_challenge(
    code_challenge_id varchar(255) NOT NULL,
    created_at timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
    code_challenge varchar(500) NOT NULL,
    code_challenge_method varchar(10) NOT NULL,
    redirect_url varchar (200) NOT NULL,
    client_id varchar(255) NOT NULL,
    username varchar (255) NOT NULL,
    response_type varchar (20) NOT NULL,
    expire_at bigint NOT NULL,
    is_challenge_used boolean NOT NULL DEFAULT false,

    CONSTRAINT CODE_CHALLENGE_PK PRIMARY KEY(code_challenge_id)
)