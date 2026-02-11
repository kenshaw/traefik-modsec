# Traefik Modsecurity Plugin

This is a fork of a fork of a fork of the original
[`traefik-modsecurity-plugin`][traefik-modsecurity-plugin].

[traefik-modsecurity-plugin]: https://github.com/madebymode/traefik-modsecurity-plugin

This fork introduces three transport-level knobs—`dialTimeoutMillis`,
`idleConnTimeoutMillis` and `maxIdleConnsPerHost`—that let you keep Traefik’s
**goroutine count** and the node’s **conn-track table** under control when your
cluster serves thousands of back-ends. In short, they allow you to:

- **Fail fast** if the ModSecurity service is unreachable (`dialTimeoutMillis`).
- **Prune** idle keep-alive sockets sooner (`idleConnTimeoutMillis`).
- **Cap** the number of idle sockets Traefik keeps per host (`maxIdleConnsPerHost`).

See: https://github.com/traefik/plugindemo#troubleshooting

---

Traefik plugin to proxy requests to a Modsecurity service, usually the a
container running [`docker.io/owasp/modsecurity-crs:nginx`][container-repo].

[container-repo]: https://github.com/coreruleset/modsecurity-crs-docker/

- [Traefik Modsecurity Plugin](#traefik-modsecurity-plugin)
  - [Demo](#demo)
  - [Usage (compose.yaml)](#usage-compose-yaml)
  - [How it works](#how-it-works)
  - [Local development (compose.local.yml)](#local-development-composelocalyml)

## Demo

Demo with WAF intercepting relative access in query param.

![Demo](./img/waf.gif)

## Usage (compose.yaml)

See [compose.yaml](compose.yaml)

```sh
# start containers
$ podman compose up -d

# test known good url (status code should be 200)
$ curl -v http://127.0.0.1/website

# test known bad url (status code should be 403)
$ curl -v http://127.0.0.1/website?test=../etc

# test bypass url (status code should be 200)
$ curl -v http://127.0.0.1/bypass?test=../etc
```

## How it works

This is a very simple plugin that proxies the query to the [OWASP
container][container-repo]. The plugin checks that the response from the [OWASP
container][container-repo] has a valid HTTP status code, before forwarding the
request.

If the [OWASP container][container-repo] responds with a status code greater
than `400`, then an error page is returned instead.

The _dummy_ service is created so the waf container forward the request to a
service and respond with 200 OK all the time.

## Configuration

| Key                              | Required? | Default      | What it does                                                                                                                                                                           |
| -------------------------------- | --------- | ------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **`modSecurityUrl`**             | **yes**   | —            | URL of the OWASP / ModSecurity service (e.g. `http://modsecurity-crs.modsecurity-crs.svc:8080`).                                                                                       |
| `timeoutMillis`                  | no        | **2000 ms**  | _Whole_ request budget (dial + request + response).                                                                                                                                    |
| `dialTimeoutMillis`              | no        | **30000 ms** | Time limit for **establishing the TCP connection** to the ModSecurity service. If the socket isn’t connected within this window, the plugin aborts with `Bad Gateway`.                 |
| `idleConnTimeoutMillis`          | no        | **90000 ms** | **How long an idle keep-alive socket can stay open** before it is closed and its goroutine reclaimed. Lowering this prevents a slow leak of goroutines under spiky traffic.            |
| `maxIdleConnsPerHost`            | no        | **2**        | Upper bound on the **number of idle sockets** the plugin keeps for `modSecurityUrl`. Set higher for very high-RPS environments, lower to conserve file descriptors / conn-track slots. |
| `jailEnabled`                    | no        | `false`      | Enables 429 “jail” for repeat offenders.                                                                                                                                               |
| `jailTimeDurationSecs`           | no        | `3600`       | How long a client IP stays in jail (seconds).                                                                                                                                          |
| `badRequestsThresholdCount`      | no        | `25`         | Number of 403 replies that trips the jail.                                                                                                                                             |
| `badRequestsThresholdPeriodSecs` | no        | `600`        | Sliding-window length (seconds) for the above threshold.                                                                                                                               |
| `unhealthyWafBackOffPeriodSecs`  | no        | `0`          | the period, in seconds, to backoff if calls to modsecurity fail. Default to 0. Default behavior is to send a 502 Bad Gateway when there are problems communicating with modsec.        |

> **NOTE:** leave a field out (or set it to `0`) to use the default shown in
> the table.
