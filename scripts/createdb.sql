drop database wwwads;
create database wwwads ;
\connect wwwads
create table arg_strings (argid serial, arg_string varchar(16) primary key );
create table request_strings (requestid serial, request_string varchar(64) primary key );
create table usernames (userid serial, username varchar(32) not null primary key);
create table notice_templates (id serial,name char(8) unique primary key,template text);
create table hosts (ip inet not null primary key, nic_handle_notified varchar(16) default null,notice_ts timestamp default null, notice_name char(8),open_proxy boolean default 'f'::bool, open_proxy_tested_at timestamp default null,freq401 float8 default 0,last_freq_computed_at timestamp default null,foreign key (notice_name) references notice_templates(name) );
create table eventrecords (eventid serial primary key,ts timestamp default now(), status int2 not null, userid int4, ip inet, requestid int4, argid int4, foreign key (userid) references usernames(userid), foreign key (ip) references hosts(ip), foreign key (requestid) references  request_strings(requestid), foreign key (argid) references arg_strings(argid));
CREATE INDEX event_ts_ip_index ON eventrecords (ts,ip);
create table blacklist (ip inet,active boolean default 'f'::bool,first_event int4, foreign key (first_event) references eventrecords(eventid), block_reason int2,  blocked_at timestamp default now(), unblocked_at timestamp default null,unblock_reason int2 default null,foreign key (ip) references hosts(ip),primary key (ip,blocked_at));
create table whitelist (ip inet unique primary key);

