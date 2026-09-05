# Blog

In this article I describe what my `phx-port` utility can do. It allows you to easily connect to all your locally running web projects (without having to remember TCP port numbers), but also experience *real* TLS access with proper domain names, all over port 443, without having to give it the keys to the kingdom.

## Managing port numbers

I was running multiple web projects on my machine, and each HTTP endpoint needed it's own TCP port to listen on. Elixir Phoenix by default uses port 4000 to listen on. Of course it's extensible and configurable, and if you meticuluously remember to e.g. set the PORT environment variable (to an unused port number) before launching Phoenix, it's all great. But LLMs made my brain and memory rot, and I can't (or don't want to remember) all that ceremony. So instead of `PORT=4010 mix phx.server`, I just wanted to say `PORT="$(gimme some free port)" mix phx.server`, and some tool should figure it out. 

That was the initial idea behind `phx-port`. When it is called in a shell script like `PORT="$(phx-port)"`, the utility looks up the current directory (treating the path as a synonym for the web app), consults it's own growing config file, and says: "Let's give `/home/chgeuer/src/webapp1` port 4012 from now on", so whenever we run `phx-port` in that directory, it returns 4012. 

## It's not Elixir-specific

Even though I called it **phx**-port (like in Elixir's Phoenix web framework), the utility is built in Rust, and doesn't care which application it's giving port numbers for. It just remembers directory-to-port numbers.

## Managing (multiple) port numbers

Often, projects need multiple ports, like one for the HTTP listener, one for the HTTPS/TLS listener, maybe one for a relational database or something else. So you can define aliases for which you want a port number, like `PORT="$(phx-port)" TLS_PORT="$(phx-port https)" DB_PORT="$(phx-port sql)" ./run-my-servers.sh`. In that case, `phx-port` gives the port of the `main` alias, but there are also ports for `https` and `sql`. 

So in my `~/.config/phx-ports.toml` file, I see something like this:

```toml
[ports]

[ports."/home/chgeuer/src/webapp1"]
main = 4012
https = 4013
sql = 4014
```

In order to get a nice overview, running `phx-port list --port-only` shows me

```
/home/chgeuer
├── src
│   ├── webapp1 ....... 4012, 4013 (https), 4014 (sql)
```

So I can easily see which projects are on which ports. And of course, I can fiddle in the config text file, or run `phx-port register` or  `phx-port delete` for CRUD-like operations.

## Discovery - via CLI, Code or browser

I also wanted a convenient way to open the corresponding web pages (because, you know, my brain doesn't remember port numbers any more).

### Opening via CLI

In a web project, I can simply run `phx-port open` and it launches the system's default browser against the right port:

```text
webapp1$ phx-port open
Opening http://localhost:4012
Opening in existing browser session.

webapp1$ 
```

### If you still use the mouse - open via Visual Studio Code

You can also install a little VS Code plugin so you can right-click your project directory in Explorer, and select the "Open in Browser (phx-port)" entry to achive the same thing.

### One web page to rule them all

However, the best thing is to run `phx-port discover`, which has phx-port to spin up a little web server, display a web page with all running projects and clickable links to their ports, and when you follow on one of the links to the project page, the `phx-port` built-in server gets notified of the click and terminates the phx-port process, so the web server doesn't run any longer. 

![](discover-screenshot.png)

On my machine, I just run the little [`omarchy-setup.sh`](../omarchy-setup.sh) script to register a keyboard shortcut to quickly bring me to the discovery page. Wham-bang, quick and easy.

## A side quest: TLS and secure all the things

So now that all gives me a slick local dev experience, I can have many web projects and hobby stuff running on my machine, each one with it's own ports, listening on localhost, discover them, cool. But - I'm also a developer who wants to fully enable security-related stuff as early as possible in a project lifecycle. That is, I want to enable https (TLS) as soon as possible. 

### Let's Encrypt over HTTP 01

**`site_encrypt`**: In the Elixir ecosystem, the wonderful Saša Jurić created a library project called [`site_encrypt`](https://github.com/sasa1977/site_encrypt); you can install that library in your public Internet-facing web project, and `site_encrypt` reaches out to the LetsEncrypt certification authority, and runs the "ACME HTTP 01" challenge. As you probably know, Let's Encrypt is a CA that issues "free" X.509 certs which you can use for enabling TLS on a web server with a production certificate. It's a great project and solution, but I can't use it as-is: The "ACME HTTP 01" challenge means that when your web server tries to convince Let's Encrypt that it owns a domain name, Let's Encrypt essentially says "Place this little secret here into your web server, we'll try to download it in a few seconds, and if we can download it, we believe that you own the web server, and we're willing to issue you the certificate."

That's a bummer, because during development I'm running stuff on my developer laptop, which is in my home LAN, behind a DSL and NAT, and Let's Encrypt cannot reach any of my web projects from the public Internet. Luckily, Let's Encrypt also offers another way to prove that I own a domain (so they're willing to issue me a certificate), the "ACME DNS 01" challenge. 

```mermaidjs
sequenceDiagram
    participant Let's Encrypt
    participant Web Project
    actor DNS@{ "type": "database" } as DNS Server

    Web Project->>Let's Encrypt: Hi, I'm this domain, give me a certificate
    Let's Encrypt-->>Web Project: Prove it by storing this challenge in your DNS server, if you can do that, I trust you
    Web Project->>DNS: Store this challenge
    Let's Encrypt->>DNS: Were they able to store my challenge there?
    Web Project->>Let's Encrypt: You should've seen I own my DNS, so can I haz cheese, please?
    Let's Encrypt-->>Web Project: Here's your production certificate    
```

So I created a little `:acme_dns` library, which supports DNSimple and Azure DNS as DNS servers, and which then handles dynamic certificate issuance for my web projects. So when I configure the public domain name to my laptop's IP (or localhost), and the web app grabs a real production cert from Let's Encrypt, now I can reach my project via HTTPS. 

### `localhost` and some funky port don't cut it anymore

So let's say for the sake of the argument I have my web project `/home/chgeuer/src/webapp1` to host the TLS endpoint **with a production grade TLS cert** on `https://localhost:4013/`. When I visit that page with the web browser, I have a set of problems, all related to the domain name. 

> Excursion -- Understanding SNI (Server Name Indication): In the dark ages of TLS, back when Transport Layer Security was called SSL (Secure Socket Layer), a web server would have a single SSL certificate, *THE* certificate. Back then, you could only have a single hostname per IP address. `https://` listens on TCP port 443, and during the establishment of the encrypted SSL tunnel, the server would be sending the certificate to the client, before the web server part would see a `Host:` HTTP header to understand which domain name the client wanted to reach. That prevented high-density hosting where you could run multiple domains on the same IP address. The "Server Name Indication (SNI)" extension to TLS allows the client (browser) to tell the web server which domain name it wants to connect to, so that if the web server hosts multiple domains, it can pick and present the right X.509 cert to the client. 

So when a web browser establishes the TLS connection to a web server, it communicates (via SNI) which domain it wants to talk to, waits for the server's TLS certificate, and ensures the certificate belongs to the visited domain. So coming back to our TLS endpoint on `https://localhost:4013/`, we now have some problems: Our web server does not have a certificate for `localhost`, it only has one for our configured domain. And when we deliver the production cert to the client, the browser will raise a security warning that the hostname (`localhost`) and the certificate's subject (e.g. `www.geuer-pollmann.de`) don't match. 

But - we can manually change the browser address, and visit `https://www.geuer-pollmann.de:4013/`, and if the DNS entry for `www.geuer-pollmann.de` would point to an IP address that our web server is listening on, then we would see our web workload, without security warnings. The last issue we have is that nasty port number: Slapping that `:4013` into the address bar sucks, it annoys my eyes, and depending on what you want to do, it might even be seen as an untrusted port (everything above port 1024 is fishy from a security perspective). 

## Would the real hostname please stand up?

So by now we have two problems: `phx-port discover` shows `https://localhost:xxxx/` links, so `localhost` and the stupid ugly port number. But - we can get creative: phx-port can scan all open ports from workloads which use `phx-port` to get a free port number, and we can establish a TLS connection, ask for the certificate, and extract the domain name from the certificate. So `phx-port` is therefore able to say `https://localhost:4013/` is actually `https://www.geuer-pollmann.de:4013/`, and show the real hostname in the discovery page. So when we follow one of those links, we immediately get to TLS endpoint with the appropriate certificate. 

The only problem left is the non-standard port.

## Let's turn `phx-port` into a reverse proxy

Then we (my coding agent and I) got creative: Instead of using `phx-port` as a glorified database for free port numbers and a temporary web server for a navigation page, we extended it to be a proper reverse proxy. A "reverse proxy" here means a web component that listens on the TLS/HTTPS standard port 443, and accepts incoming connection requests, and forwards stuff to the workload in the back. So that when I connect to `https://www.geuer-pollmann.de/` (implicitly that's `https://www.geuer-pollmann.de:443/`), we would want to take that connection and forward traffic to the web server in the backend (in that case our workload that listens on port `TCP/4013`). 

### Who owns the private key?

However, there's a new problem: Most reverse proxies are *terminating* the incoming TLS connections. "TLS Termination" means that the reverse proxy (like Nginx) has access to the web server's TLS certificate (and the private key!), so the reverse proxy pretends towards the browser to be the actual web server, it then decrypts the full request, and establishes a new TCP session to the actual downstream web server (https://localhost:4013 in our case), and forward the request to the server, and forward the server's response back to the client. That all sucks for multiple reasons:

- I don't like giving the reverse proxy the private keys. Ideally TLS should only be configured in my web workload (my `/home/chgeuer/src/webapp1` project). I don't want to have a proliferation of key material here.
- The web workload doesn't see the client IP address: From my web project's perspective, the incoming TCP/TLS connection comes from the reverse proxy, not the user's web browser. One approach to 'solve' this problem is by having the reverse proxy to inject additional HTTP headers into the request, like an `X-Forwarded-For:` header, by which the reverse proxy says: "Hey, you see me calling you from localhost, but from what I can see, the actual request came from 91.34.98.103`." These things can easily be spoofed, the client itself could put in own HTTP headers, and it's overall just very messy
- Security: I totally don't like some intermediary in the middle (`phx-port` in our case) to terminate/decrypt the session, because then it's no longer end-to-end-security, but just link encryption (even if the last hop is on the same computer)
- Cryptographic Performance: Decrypting the incoming request's TLS, just to establish a new TLS session to the origin server (our :4013 server) is just useless overhead, given we're not doing any real processing with the request

### Peeking into ClientHello

So all that sucks, so what can we do instead? When there's an incoming TCP/TLS connection to `phx-port`, the proxy **peeks** at the incoming network stream. Like Al Pacino said in "The Devil's Advocate": **Look, but don't touch. Touch, but don't taste. Taste, don't swallow.** We don't want to swallow bytes from the incoming network stream, we just want to look. We just look enough to see the web browser's TLS stack's ClientHello message in which the browser tells us which domain it wants to talk to. 

> There's a DNS configuration called "Encrypted Client Hello (ECH)" in which site owners can tell browsers to avoid sending the desired host's domain name in plaintext in the ClientHello TLS packet. We hope it's not configured for our own domains.

So now `phx-port` can 'see' for which web domain the request came in on standard port `:443`. So in the back, `phx-port` (running as a service) scans all local web apps to find out who has which TLS certificate and domain, and it sees the incoming connection's ClientHello message with the desired domain. Now phx-port can accept the TCP connection, and relay the **encrypted** byte stream to the backend service. 

What do we get from that? We solve a few of the previously mentioned problems: 

- Our `phx-port` service does not have to have access to the web app's private keys; it figures out from ClientHello which destination to route to, but doesn't have to decrypt, so no need for private key.
- Because we don't decrypt the session, well, we don't decrypt the session. Which is good both for security (no plaintext to protect) and performance (no decryption and re-encryption).

By now we have a reverse proxy which can take incoming TLS connections on standard port 443, and route it to the correct web app on our laptop. By the way, that web app itself even doesn't have to listen on the laptop's public IP, it's sufficient to listen just on localhost/127.0.0.1, so no direct exposure of the web app to the outside world. 

## Solving the last issues: network performance and IP address visibility

By now, our `phx-port` reverse proxy relays encrypted TCP connections, i.e. it terminates the incoming TCP connection, establishes a new TCP connection to the web workload, and forwards (relays) encrypted byte streams in both directions. Therefore, we still have two problems remaining: From a performance perspective, phx-port shoveling bytes forth and back kind-of sucks, by a lot. And - our web workload still cannot see the real client's IP address (because relayed connections come from phx-port running on localhost). 

Then I remembered an interesting [conversation on Twitter](https://x.com/chris_mccord/status/2029630330630508929) with Elixir Phoenix inventor Chris McCord, about the possibility to use `SCM_RIGHTS` on Linux (and BSD Darwin/MacOS) to hand-over an existing (established) TCP socket to a completely different OS process. Back then I did a few experiments in https://github.com/chgeuer/blue_green where that mechanism could be used to do blue/green deployments, or hand-over an establied connection from an Erlang process to a Rust process. 

Which made me think: that's exactly what I'm having now - A Rust process (`phx-port`) that owns an incoming TCP/TLS connection, and would like a downstream service (like a Phoenix web app) to actually own and control the connection (and the established socket). A while back, the Phoenix project moved from Erlang Cowboy over to a new underlying web stack, namely [Matt Trudel's](https://github.com/mtrudel) [Thousand Island](https://github.com/mtrudel/thousand_island) and [Bandit](https://github.com/mtrudel/bandit). 

My web app already uses Thousand Island (which owns the TCP socket listener), and Bandit (which routes the HTTP request towards Plug and Phoenix). So I was wondering: Can we have the Phoenix web app have both, listen on the TLS port (e.g. `:4013`) for incoming TCP/TLS connections, but *also* allow an external process like `phx-port` to hand-over established sockets? 

That is what the [`phx_port_handoff` Elixir module](https://github.com/chgeuer/phx-port/tree/master/phx_port_handoff) in our project does. In addition to the regular `MyAppWeb.Endpoint`, we have an additional supervised `PhxPortHandoff` child that accepts established sockets handed over from `phx-port` into our web app, and which then funnels these into the regular Bandit/Phoenix request handling pipeline:

```elixir
def start(_type, _args) do
  project = File.cwd!()
  https = Application.fetch_env!(:my_app, MyAppWeb.Endpoint)[:https]

  children = [
    PhxPortHandoff.bandit_child_spec(MyAppWeb.Endpoint, project, "https", https),
    MyAppWeb.Endpoint
  ]

  Supervisor.start_link(children,
    strategy: :one_for_one,
    name: MyApp.Supervisor
  )
end
```

## The result

