# PEEK V2 Narrative Overview

## What Is This Thing?

PEEK, which stands for Port Enumeration and Evaluation Kit, is a network security scanner built for teams who need to regularly audit their infrastructure. Think of it as an orchestration layer that ties together battle-tested security tools like Nmap and Nuclei, wraps them in a clean web interface, and adds the ability to compare scans over time to spot changes in your attack surface.

The core idea is simple. You give PEEK a list of IP addresses or hostnames, it discovers what ports are open, figures out what services are running on those ports, and then throws vulnerability checks at each service to find potential security issues. All of this gets stored in a database so you can come back later, run another scan, and see what changed.

## Who Would Use This?

This tool fits a few different scenarios. Security teams doing periodic assessments of their network infrastructure would find it useful. IT administrators who want to track what services are exposed across their environment could use it for asset discovery. Penetration testers doing reconnaissance as part of an engagement might spin it up. Really, anyone who needs to answer the question "what's running on my network and is any of it vulnerable" could benefit.

The historical comparison feature is particularly valuable for organizations with compliance requirements. If you need to demonstrate that you're actively monitoring your infrastructure and addressing vulnerabilities, PEEK gives you timestamped evidence of your scanning activity and the ability to show progress over time.

## How Does It Work Under the Hood?

The architecture has four main pieces that work together. There's a React frontend that provides the user interface for creating scans, viewing results, and configuring settings. Behind that sits a FastAPI backend that handles authentication, stores data in SQLite, and exposes a REST API. The actual scanning work happens in Celery workers that run asynchronously. And Redis acts as the message broker that coordinates everything.

When you kick off a scan, here's what actually happens. The backend creates database records for the scan and its targets, then hands the work off to Celery. The worker starts with Nmap in discovery mode to find open ports. Once it knows which ports are open, it runs Nmap again with service detection to identify what's actually running on each port. This is where it figures out if port 80 is running Apache or Nginx, or if that weird high port is actually an SSH server.

After service detection comes the interesting part. For each discovered port, the system consults something called a Nuclei Profile. This is a mapping defined in a YAML configuration file that says things like "if you see an HTTP service, scan it with these specific vulnerability templates" or "if you find SSH, run these checks." The profiles control target formatting, which templates to use, rate limiting, and timeouts. This is where the intelligence lives.

Nuclei then runs against each port with the appropriate configuration, producing JSONL output that gets parsed and stored as vulnerability records. Each vulnerability links back to the specific port and tool execution that found it, so you have full traceability.

There's also an optional ssh-audit phase that runs specialized SSH security analysis on any SSH ports it finds. This catches things like weak key exchange algorithms or deprecated ciphers that Nuclei might miss.

## The Two Scan Modes

PEEK supports two scanning modes that represent different tradeoffs between speed and thoroughness. Fast mode uses targeted template tags based on the detected service. If it sees Apache, it runs Apache-specific checks. If it finds MySQL, it runs database checks. This is quicker but might miss things that generic templates would catch.

Deep mode throws the kitchen sink at everything. For HTTP services, it runs comprehensive template coverage without tag filtering. This takes longer and generates more traffic, but you're less likely to miss something. Deep mode is also where you'll see low severity and informational findings, which fast mode typically skips.

The severity filtering is configurable. By default, scans look for critical, high, medium, low, and informational findings. But you can tune this in the scan configuration if you only want to see the serious stuff.

## Things That Will Trip You Up

Let me save you some debugging time by covering the common gotchas.

First, if you're running this on Docker Desktop for Mac, you'll run into networking issues with Nmap. The SYN scan mode that Nmap uses by default doesn't work properly through Docker Desktop's virtualization layer. Ports will show up as filtered instead of open. The fix is to switch to TCP connect scan mode by changing the Nmap arguments in your scan configuration.

Second, if Nuclei isn't finding vulnerabilities on ports where Nmap detected services, there are several things to check. The scan mode matters. Fast mode only runs targeted checks, so if a service doesn't have a matching profile, it might get skipped entirely. There's also tag validation happening behind the scenes. If a profile specifies tags that don't match any installed Nuclei templates, that port gets skipped with a warning in the worker logs. You'll want to check those logs to see what's actually happening.

Third, the Nuclei profiles configuration file is central to everything. If a service type isn't defined there, PEEK won't know how to scan it unless you've enabled the fallback option for unknown services. The file lives at backend slash config slash nuclei underscore profiles dot yaml, and understanding its structure is essential for customizing scan behavior.

Fourth, watch your timeouts and rate limits. Nuclei can be aggressive, and some profiles intentionally throttle to avoid overwhelming targets or triggering rate limiting on the target side. If scans seem slow, check whether the profile for that service type has a restrictive rate limit set.

## The Data Model

Understanding how data is organized helps when you're troubleshooting or building on top of the system. At the top level you have Scans. Each Scan contains one or more Scan Targets, which are individual IP addresses or hosts. Each Scan Target has Ports discovered on it. Vulnerabilities link to Scan Targets, Ports, and the specific Tool Execution that found them.

The Tool Execution records are particularly useful for debugging. They store the exact command line that was run, the raw output from the tool, the exit code, and timing information. If something went wrong, these records tell you exactly what happened.

## Extending The System

Adding support for new scanning tools follows a predictable pattern. You create a tool wrapper in the tools directory that knows how to build command lines and execute the tool. You create a parser in the parsers directory that knows how to read the tool's output format and extract findings. Then you add a new phase to the scan task orchestration that calls your wrapper and parser at the appropriate point in the pipeline.

The Nuclei profiles are easier to extend. It's just YAML configuration. If you need to add support for a new service type, you add an entry to the profiles file specifying how that service should be targeted, what tags to use, and any special rate limiting or timeout handling.

## Running It Locally

For development, you'll typically run the frontend and backend separately with hot reloading. The frontend is a standard Vite setup, so npm run dev gets you going. The backend needs both the FastAPI server and at least one Celery worker running. The worker is what actually executes scans, so nothing will happen without it.

For a more production-like setup, docker compose brings up everything including Redis and optional services like OWASP ZAP. The compose file defines the full stack with appropriate volume mounts and environment variables.

The default credentials are admin slash admin, which you absolutely should change if you're running this anywhere that matters.

## The Frontend Stack

The UI is built with React and TypeScript, using Vite as the build tool. State management uses Zustand for global state and TanStack Query for server state and caching. Routing is handled by TanStack Router. The component library is Headless UI with Tailwind CSS for styling.

The main views are the scan list, scan detail page that shows ports and vulnerabilities, the new scan form, and configuration management. The API clients live in a dedicated directory and handle all communication with the backend.

## Final Thoughts

PEEK is essentially an opinionated orchestration layer for security scanning. The value isn't in the individual tools, which you could run yourself from the command line. The value is in the workflow automation, the historical tracking, the service-aware scanning logic, and having everything accessible through a web interface.

If you're working with this codebase, spend time understanding the scan task orchestration in scan underscore tasks dot py and the Nuclei profile mapping in service underscore profile dot py. Those two files contain most of the interesting logic. The rest is fairly standard web application plumbing.

The documentation in the docs directory is thorough and worth reading, particularly the scan lifecycle document that traces a scan from user action through to stored results. The architecture and data model documents provide good mental models for how everything fits together.
