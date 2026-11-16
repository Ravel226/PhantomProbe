#!/usr/bin/env python3
"""
What NVD calls each technology.

Data only. A banner says "nginx" or "node"; NVD files vulnerabilities under a
vendor:product pair such as f5:nginx, and that pair is not guessable: a wrong
one returns a clean empty result rather than an error. Every pair here was
checked against the live API, and scripts/audit_cpe_mapping.py repeats the
check.

The tables are reached through CVEMatcher (CVEMatcher.CPE_MAPPING and so on),
which is how the audit script and the tests address them.
"""


# Technology to CPE vendor/product mapping
CPE_MAPPING = {
    'php': {'vendor': 'php', 'product': 'php'},
    # NVD files modern nginx CVEs under f5, which acquired it:
    # nginx:nginx returns 2 results where f5:nginx returns 41.
    'nginx': {'vendor': 'f5', 'product': 'nginx'},
    'apache': {'vendor': 'apache', 'product': 'http_server'},
    'openssl': {'vendor': 'openssl', 'product': 'openssl'},
    'mysql': {'vendor': 'oracle', 'product': 'mysql'},
    'postgresql': {'vendor': 'postgresql', 'product': 'postgresql'},
    'redis': {'vendor': 'redis', 'product': 'redis'},
    'mongodb': {'vendor': 'mongodb', 'product': 'mongodb'},
    'node.js': {'vendor': 'nodejs', 'product': 'node.js'},
    # expressjs:express returns nothing; the CPE is under openjsf.
    'express': {'vendor': 'openjsf', 'product': 'express'},
    'django': {'vendor': 'djangoproject', 'product': 'django'},
    'flask': {'vendor': 'palletsprojects', 'product': 'flask'},
    'wordpress': {'vendor': 'wordpress', 'product': 'wordpress'},
    'drupal': {'vendor': 'drupal', 'product': 'drupal'},
    'joomla': {'vendor': 'joomla', 'product': 'joomla'},
    'tomcat': {'vendor': 'apache', 'product': 'tomcat'},
    'iis': {'vendor': 'microsoft', 'product': 'internet_information_server'},
    'dotnet': {'vendor': 'microsoft', 'product': '.net_framework'},
    'java': {'vendor': 'oracle', 'product': 'jdk'},
    'python': {'vendor': 'python', 'product': 'python'},
    'ruby': {'vendor': 'ruby-lang', 'product': 'ruby'},

    # Everything below was confirmed against the live NVD API before
    # being added: a vendor guessed wrong returns nothing at all, which
    # is how expressjs:express sat here matching zero CVEs. Vue.js is
    # deliberately absent; NVD has no CPE for it under any spelling.
    'litespeed': {'vendor': 'litespeedtech', 'product': 'litespeed_web_server'},
    'openresty': {'vendor': 'openresty', 'product': 'openresty'},
    'lighttpd': {'vendor': 'lighttpd', 'product': 'lighttpd'},
    'caddy': {'vendor': 'caddyserver', 'product': 'caddy'},
    'haproxy': {'vendor': 'haproxy', 'product': 'haproxy'},
    'traefik': {'vendor': 'traefik', 'product': 'traefik'},
    'envoy': {'vendor': 'envoyproxy', 'product': 'envoy'},
    'varnish': {'vendor': 'varnish_cache_project', 'product': 'varnish_cache'},
    'jetty': {'vendor': 'eclipse', 'product': 'jetty'},
    'gunicorn': {'vendor': 'gunicorn', 'product': 'gunicorn'},
    'werkzeug': {'vendor': 'palletsprojects', 'product': 'werkzeug'},
    'tornado': {'vendor': 'tornadoweb', 'product': 'tornado'},
    'asp.net core': {'vendor': 'microsoft', 'product': 'asp.net_core'},
    'laravel': {'vendor': 'laravel', 'product': 'laravel'},
    'rails': {'vendor': 'rubyonrails', 'product': 'rails'},
    'spring': {'vendor': 'vmware', 'product': 'spring_framework'},
    'struts': {'vendor': 'apache', 'product': 'struts'},
    'symfony': {'vendor': 'sensiolabs', 'product': 'symfony'},
    'fastapi': {'vendor': 'tiangolo', 'product': 'fastapi'},
    'next.js': {'vendor': 'vercel', 'product': 'next.js'},
    'nuxt': {'vendor': 'nuxt', 'product': 'nuxt'},
    'angular': {'vendor': 'angular', 'product': 'angular'},
    'react': {'vendor': 'facebook', 'product': 'react'},
    'jquery': {'vendor': 'jquery', 'product': 'jquery'},
    'bootstrap': {'vendor': 'getbootstrap', 'product': 'bootstrap'},
    'magento': {'vendor': 'magento', 'product': 'magento'},
    'typo3': {'vendor': 'typo3', 'product': 'typo3'},
    'ghost': {'vendor': 'ghost', 'product': 'ghost'},
    'mediawiki': {'vendor': 'mediawiki', 'product': 'mediawiki'},
    'moodle': {'vendor': 'moodle', 'product': 'moodle'},
    'phpmyadmin': {'vendor': 'phpmyadmin', 'product': 'phpmyadmin'},
    'confluence': {'vendor': 'atlassian', 'product': 'confluence'},
    'jira': {'vendor': 'atlassian', 'product': 'jira'},
    'jenkins': {'vendor': 'jenkins', 'product': 'jenkins'},
    'gitlab': {'vendor': 'gitlab', 'product': 'gitlab'},
    'grafana': {'vendor': 'grafana', 'product': 'grafana'},
    'elasticsearch': {'vendor': 'elastic', 'product': 'elasticsearch'},
    'kibana': {'vendor': 'elastic', 'product': 'kibana'},
    'mariadb': {'vendor': 'mariadb', 'product': 'mariadb'},
    'memcached': {'vendor': 'memcached', 'product': 'memcached'},
    'rabbitmq': {'vendor': 'pivotal_software', 'product': 'rabbitmq'},
    'openssh': {'vendor': 'openbsd', 'product': 'openssh'},
    'proftpd': {'vendor': 'proftpd', 'product': 'proftpd'},
    'vsftpd': {'vendor': 'vsftpd_project', 'product': 'vsftpd'},
    'postfix': {'vendor': 'postfix', 'product': 'postfix'},
    'exim': {'vendor': 'exim', 'product': 'exim'},
    'dovecot': {'vendor': 'dovecot', 'product': 'dovecot'},
    'samba': {'vendor': 'samba', 'product': 'samba'},
    'bind': {'vendor': 'isc', 'product': 'bind'},
    'docker': {'vendor': 'docker', 'product': 'docker'},
    'kubernetes': {'vendor': 'kubernetes', 'product': 'kubernetes'},
    'golang': {'vendor': 'golang', 'product': 'go'},
    'perl': {'vendor': 'perl', 'product': 'perl'},
}

# Further identifiers NVD files the same software under. A pair that
# returns results can still be incomplete, which is quieter than a pair
# that returns nothing: f5:nginx holds 41 CVEs and looks healthy, yet NVD
# files the newer nginx CVEs under f5:nginx_open_source instead. For
# nginx 1.24.0 the first identifier returned 2 CVEs and the second 15
# more, nine of them scored 7.0 or higher (checked 2026-11-16). Every
# entry is queried alongside the primary mapping and merged by CVE id.
#
# An identifier is listed only when it names the same software and, asked
# about a real version, returned CVEs the primary did not. Each comment
# records that check: the version asked about, how many CVEs the primary
# returned, and how many more only this identifier returned (NVD,
# 2026-11-16). Identifiers that exist but added nothing are left out, as
# are those naming a different edition with its own version numbering.
CPE_SIBLINGS = {
    # 1.24.0: 2, +15
    'nginx': [{'vendor': 'f5', 'product': 'nginx_open_source'}],
    # 8.0.30: 147, +155 under mysql_server. 5.0.45: 206, +6 under mysql:mysql.
    'mysql': [
        {'vendor': 'oracle', 'product': 'mysql_server'},
        {'vendor': 'mysql', 'product': 'mysql'},
    ],
    # 3.2.0: 22, +12
    'redis': [{'vendor': 'redislabs', 'product': 'redis'}],
    # 3.9.0: 0, +125. NVD spells the product with its exclamation mark, and
    # the plain spelling returned nothing at all for this version.
    'joomla': [{'vendor': 'joomla', 'product': 'joomla\\!'}],
    # 6.1.26: 12, +2
    'jetty': [{'vendor': 'mortbay', 'product': 'jetty'}],
    # 3.0.0: 32, +3 under springsource. 4.0.0: 34, +4 under pivotal_software.
    'spring': [
        {'vendor': 'springsource', 'product': 'spring_framework'},
        {'vendor': 'pivotal_software', 'product': 'spring_framework'},
    ],
    # 9.3.0: 5, +1
    'next.js': [{'vendor': 'zeit', 'product': 'next.js'}],
    # 2.4.3: 8, +126. Adobe Commerce is a separate edition and is left out.
    'magento': [{'vendor': 'adobe', 'product': 'magento'}],
    # 7.13.0: 0, +14 across the two (13 each, 12 shared). The plain product
    # name returned nothing for this version.
    'confluence': [
        {'vendor': 'atlassian', 'product': 'confluence_server'},
        {'vendor': 'atlassian', 'product': 'confluence_data_center'},
    ],
    # 8.13.0: 20, +45 across the two (43 and 37, 35 shared).
    'jira': [
        {'vendor': 'atlassian', 'product': 'jira_server'},
        {'vendor': 'atlassian', 'product': 'jira_data_center'},
    ],
    # 6.0: 12, +7. 7.5: 0, +3.
    'iis': [{'vendor': 'microsoft', 'product': 'internet_information_services'}],
    # 1.4.2: 13, +2
    'elasticsearch': [{'vendor': 'elasticsearch', 'product': 'elasticsearch'}],
    # 4.1.0: 29, +2
    'kibana': [{'vendor': 'elasticsearch', 'product': 'kibana'}],
    # 3.8.9: 0, +8 across the two (5 of them under vmware). 3.12.0: 0, +2
    # under broadcom. The primary returned nothing for either version.
    'rabbitmq': [
        {'vendor': 'vmware', 'product': 'rabbitmq'},
        {'vendor': 'broadcom', 'product': 'rabbitmq_server'},
    ],
    # 1.7.12: 53, +1
    'traefik': [{'vendor': 'containous', 'product': 'traefik'}],
    # 6.0.0: 3, +5
    'varnish': [{'vendor': 'varnish-software', 'product': 'varnish_cache'}],
    # 8.0.0: 2, +5
    'laravel': [{'vendor': 'laravel', 'product': 'framework'}],
    # 3.2.0: 59, +7
    'rails': [{'vendor': 'rubyonrails', 'product': 'ruby_on_rails'}],
    # 20.10.5: 0, +16 across the two (14 and 4, 2 shared). The primary
    # returned nothing for this version.
    'docker': [
        {'vendor': 'mobyproject', 'product': 'moby'},
        {'vendor': 'docker', 'product': 'engine'},
    ],
}

# Measured the same way and left out, so nobody has to measure them again
# without a reason. Added nothing at the version tested: joyent:node.js
# (0.10.40), jetty:jetty (6.1.26), cloudbees:jenkins (1.609),
# varnish-cache:varnish (6.0.0), nuxtjs:nuxt.js (2.15.0), beasts:vsftpd
# (2.3.4), university_of_cambridge:exim (4.69). A different edition or
# product that a banner cannot tell apart: adobe:commerce,
# litespeedtech:openlitespeed, angularjs:angular.js. Exists but was not
# tested against a version: nginx:nginx (2 CVEs, both from 2009). Not in NVD
# at all: twitter:bootstrap, vmware:rabbitmq_server, symfony:symfony,
# tryghost:ghost, danga:memcached, expressjs:express.

# Technologies a script URL can reveal. A script path names what the
# browser runs, never what the server runs, so "/js/spring-1.2.0.js" must
# not be read as the Spring Framework.
CLIENT_SIDE_TECH = frozenset(
    {'jquery', 'bootstrap', 'react', 'angular', 'next.js', 'nuxt'}
)


# Spellings a banner may use, mapped onto the CPE_MAPPING keys. Without
# this, "node" was captured but thrown away, because the mapping key is
# "node.js": Node was never once correlated.
TECH_ALIASES = {
    "php": "php",
    "nginx": "nginx",
    "apache": "apache",
    "httpd": "apache",
    "openssl": "openssl",
    "mysql": "mysql",
    "postgresql": "postgresql",
    "postgres": "postgresql",
    "redis": "redis",
    "mongodb": "mongodb",
    "tomcat": "tomcat",
    "iis": "iis",
    "node.js": "node.js",
    "nodejs": "node.js",
    "node": "node.js",
    "express": "express",
    "django": "django",
    "flask": "flask",
    "wordpress": "wordpress",
    "drupal": "drupal",
    "joomla": "joomla",
    "python": "python",
    "ruby": "ruby",
    "java": "java",
    "asp.net": "dotnet",
    "dotnet": "dotnet",
    "litespeed": "litespeed",
    "openresty": "openresty",
    "lighttpd": "lighttpd",
    "caddy": "caddy",
    "haproxy": "haproxy",
    "traefik": "traefik",
    "envoy": "envoy",
    "varnish": "varnish",
    "jetty": "jetty",
    "gunicorn": "gunicorn",
    "werkzeug": "werkzeug",
    "tornado": "tornado",
    "asp.net core": "asp.net core",
    "kestrel": "asp.net core",
    "laravel": "laravel",
    "rails": "rails",
    "spring": "spring",
    "struts": "struts",
    "symfony": "symfony",
    "fastapi": "fastapi",
    "next.js": "next.js",
    "nextjs": "next.js",
    "nuxt": "nuxt",
    "nuxt.js": "nuxt",
    "angular": "angular",
    "react": "react",
    "jquery": "jquery",
    "bootstrap": "bootstrap",
    "magento": "magento",
    "typo3": "typo3",
    "ghost": "ghost",
    "mediawiki": "mediawiki",
    "moodle": "moodle",
    "phpmyadmin": "phpmyadmin",
    "confluence": "confluence",
    "jira": "jira",
    "jenkins": "jenkins",
    "gitlab": "gitlab",
    "grafana": "grafana",
    "elasticsearch": "elasticsearch",
    "kibana": "kibana",
    "mariadb": "mariadb",
    "memcached": "memcached",
    "rabbitmq": "rabbitmq",
    "openssh": "openssh",
    "proftpd": "proftpd",
    "vsftpd": "vsftpd",
    "postfix": "postfix",
    "exim": "exim",
    "dovecot": "dovecot",
    "samba": "samba",
    "bind": "bind",
    "docker": "docker",
    "kubernetes": "kubernetes",
    "k8s": "kubernetes",
    "golang": "golang",
    "perl": "perl",
}
