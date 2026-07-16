17.53
existing_human_decision existing_human_gt_behavior existing_human_gt_chain_valid existing_human_gt_root_cause existing_human_notes existing_reviewer existing_review_status
001
benign,no_closed_chain_intended_wallet_agent_cli,FALSE,benign_intended_external_agent_wallet_workflow,"The skill documents an A2A/x402 wallet CLI with user-directed agent URLs, registry search/register, payment signing, and local wallet management. Although local private keys are stored on disk and the functionality is sensitive, the file includes explicit user-facing warnings and does not show a concrete malicious source-to-external-sink or setup-control chain. Runtime was skipped and ProvLoom reported no_closed_chain, so I treat this as intended high-risk wallet functionality rather than confirmed abuse.",唐健,reviewed  
002
ambiguous,runtime_sensitive_file_to_external_registration_endpoint,TRUE,llm_induced_external_action,"The runtime chain links /etc/hosts to an HTTP request and then to https://api.abund.ai/api/v1/agents/register. This is a concrete non-LLM external endpoint and should be treated as suspicious. However, this skill is not among the user-confirmed malicious samples in the screenshot, so I mark it as ambiguous rather than confirmed malicious.",唐健,reviewed  
003
benign,no_closed_chain_sdk_sandbox_and_disk_tooling,FALSE,benign_developer_sdk_documentation,"The skill describes Acontext SDK integration patterns, including disk tools, sandbox execution, artifact storage, and session management. These are broad developer capabilities and explain why static scanners flag shell/process behavior, but the reviewed SKILL.md does not prescribe sensitive-file exfiltration, malicious persistence, or transfer of control to an attacker-controlled endpoint. ProvLoom found no_closed_chain, so I mark it benign.",唐健,reviewed  
004
benign,no_closed_chain_local_after_effects_automation,FALSE,benign_local_application_automation,"The skill automates Adobe After Effects through local ExtendScript and osascript workflows. It includes potentially powerful local file/process operations and asks that AE allow scripts to write files and access network, but the instructions are scoped to user-requested project automation, include confirmation gates for destructive operations, and do not close a malicious external sink or setup-control chain. I treat the scanner findings as capability-driven false positives.",唐健,reviewed  
005
benign,no_closed_chain_adr_documentation_workflow,FALSE,benign_documentation_and_local_script_workflow,"The skill is an ADR authoring and maintenance workflow. It instructs agents to scan a repo, draft ADR files, and optionally run local Node scripts for creating or updating ADRs. There is no external exfiltration endpoint, malicious installer, persistence mechanism, or closed trust-boundary to impact path in the reviewed SKILL.md. Static alerts appear to come from ordinary repo scanning and local script references.",唐健,reviewed

006

benign,no_closed_chain_multi_llm_spec_debate_workflow,FALSE,benign_external_model_orchestration,"The skill orchestrates adversarial review of PRDs or technical specs using configured LLM APIs, Bedrock, Codex CLI, Gemini CLI, and local debate scripts. It does involve external model calls and optional CLI installation, but these are explicit user-facing setup and review steps rather than a hidden exfiltration, persistence, or malicious setup-control chain. Runtime was skipped and ProvLoom reported no_closed_chain, so I mark it benign.",唐健,reviewed

007

ambiguous,high_impact_dead_mans_switch_executor_and_crypto_transfer,FALSE,risky_autonomous_posthumous_action_design,"The skill implements a digital legacy agent that can trigger messages, emails, account-closure workflows, social posts, webhook calls, ghost-mode responses, and optional crypto or mortality-pool transfers after a heartbeat/escalation process. These are high-impact autonomous actions, but the SKILL.md frames them as owner-approved, consent-first, local-first workflows and does not show a malicious external endpoint, remote installer, or attacker-controlled persistence chain. I therefore mark it ambiguous rather than confirmed malicious.",唐健,reviewed

008

benign,no_closed_chain_local_browser_relay,FALSE,benign_user_attached_browser_read_tooling,"The skill describes a local Agent Browser Relay that reads metadata, DOM text, screenshots, and structured payloads from an explicitly attached Chrome tab through localhost. It includes human attach requirements, lease-scoped tab IDs, and prohibitions against taking over random browser windows. Although browser-page reading is sensitive and scanners flag it, the reviewed instructions do not close a malicious external exfiltration or setup-control chain.",唐健,reviewed

009

ambiguous,instruction_derived_external_agent_install_and_persistence,TRUE,risky_external_agent_installation_with_recurring_execution,"The documentation-level evidence contains external agent installation semantics and LaunchAgent/launchctl-style persistence setup. This is security-relevant and the recovered instruction chain is valid, but the sample is not confirmed malicious in the screenshot, so the final label is ambiguous.",唐健,reviewed

010

ambiguous,no_closed_chain_delegated_defi_borrowing_agent,FALSE,risky_autonomous_financial_delegation_design,"The skill enables an agent wallet to borrow and repay assets through Aave credit delegation, with debt accruing against the delegator's collateral. This is financially sensitive and grants the agent autonomous borrowing capability, but the SKILL.md also describes explicit delegation approval, safety checks, health-factor limits, per-transaction caps, and refusal rules. I do not see a malicious source-to-sink or instruction-derived attacker-control chain, so I mark it ambiguous because of high-impact financial risk rather than confirmed malicious.",唐健,reviewed

011

benign,no_closed_chain_user_directed_gemini_research_uploads,FALSE,benign_external_research_api_workflow,"The skill performs deep research through Google Gemini APIs and can upload user-specified local context files to Gemini file-search stores. This is privacy-sensitive, but the SKILL.md makes the external API and upload behavior explicit, excludes common secrets and binary/build directories, supports dry-run and cost guards, and auto-deletes ephemeral stores by default. I do not see a malicious closed source-to-sink chain beyond intended user-directed RAG upload functionality.",唐健,reviewed

012

ambiguous,no_closed_chain_agent_orchestration_with_cron_and_bypass_flags,FALSE,risky_local_agent_lifecycle_orchestration,"The skill manages employee agents in tmux sessions, can start/stop agents, send tasks, sync cron schedules, run heartbeats, and includes launcher examples with dangerous approval/sandbox bypass flags. These capabilities are powerful and could amplify misuse, but the reviewed SKILL.md presents them as local agent lifecycle management and does not close a malicious external exfiltration, remote installer, or persistence-to-impact chain beyond intended scheduling/orchestration features. Runtime was skipped and ProvLoom reported no_closed_chain, so I mark it ambiguous because of operational risk rather than confirmed malicious intent.",唐健,reviewed

013

benign,no_closed_chain_social_posting_api_workflow,FALSE,benign_user_authorized_social_media_posting,"The skill creates, schedules, uploads media for, and manages posts through the Post Bridge API. It involves external API calls and can publish to multiple social platforms, but the SKILL.md requires API-key setup, connected user accounts, draft mode for review, confirmation before irreversible posting unless explicitly requested, and automation rules against spam or fake engagement. There is no closed malicious source-to-external-sink or setup-control chain, so I treat scanner findings as capability-driven.",唐健,reviewed

014

benign,no_closed_chain_framework_best_practices_documentation,FALSE,benign_static_development_guidance,"The skill is a NestJS best-practices guide with architecture, dependency injection, security, performance, testing, database, API, microservice, and DevOps rules. It points agents to local rule files and a compiled AGENTS.md guide, but does not instruct sensitive data transfer, external control transfer, persistence, or malicious command execution. ProvLoom found no_closed_chain, so I mark it benign.",唐健,reviewed

015

benign,no_closed_chain_agent_documentation_generator,FALSE,benign_repo_documentation_and_verification_workflow,"The skill generates and verifies AGENTS.md and related AI-agent rule files using local bash, jq, git, grep, and find scripts. It scans repositories and may execute verification commands, which explains static shell/process findings, but its purpose is documentation generation and freshness checking. I do not see an external exfiltration endpoint, malicious installer, persistence mechanism, or closed instruction-derived impact chain.",唐健,reviewed

016

benign,no_closed_chain_os_keychain_secret_management,FALSE,benign_secret_management_workflow,"The skill manages secrets through the OS keychain and injects selected values into .env files without printing secret contents. It is sensitive because it handles credentials and modifies environment files, but the instructions emphasize never exposing values, listing names first, and reporting only configured/missing status. I do not see a malicious exfiltration endpoint, attacker-controlled setup chain, or closed source-to-sink path.",唐健,reviewed

017

benign,no_closed_chain_codebase_diagram_generation,FALSE,benign_architecture_documentation_workflow,"The skill analyzes a codebase and generates or updates Excalidraw architecture diagrams. It uses read/search/write and local Node scripts to create diagram files, which explains process and shell findings, but the behavior is scoped to documentation and visualization. There is no evidence of sensitive data exfiltration, persistence, remote installer execution, or a closed malicious instruction-derived chain.",唐健,reviewed

018

benign,no_closed_chain_static_materialize_documentation,FALSE,benign_database_documentation_reference,"The skill is a Materialize documentation index for SQL syntax, ingestion, concepts, integrations, security, and deployment guidance. It points agents to local documentation files and includes ordinary references to sources, sinks, APIs, and external integrations as product documentation. There is no closed runtime or instruction-derived malicious chain, so the scanner findings appear documentation-driven.",唐健,reviewed

019

benign,no_closed_chain_saas_auth_billing_integration_docs,FALSE,benign_outseta_integration_guidance,"The skill documents how to integrate Outseta for SaaS authentication, billing, CRM, support, JWT validation, webhooks, and frontend widgets. It references external CDN/API endpoints and templates, but these are expected integration instructions for a SaaS platform and include security guidance such as JWT and webhook signature verification. I do not see an attacker-controlled installation path, persistence mechanism, or malicious source-to-sink chain.",唐健,reviewed

020

ambiguous,instruction_derived_remote_install_global_install_and_persistence_context,TRUE,risky_documented_supply_chain_and_environment_control,"The recovered instruction-level chain includes a remote install script, global npm installation, and persistence-related documentation. The evidence is instruction-derived rather than runtime-observed. Because the package appears to be positioned as an audit/security tool and is not user-confirmed malicious in the screenshot, mark as ambiguous instead of malicious.",唐健,reviewed


021

ambiguous,no_closed_chain_agent_social_identity_and_onchain_registration,FALSE,risky_onchain_wallet_identity_setup,"The skill guides an agent through Farcaster identity setup, ERC-8004 registration on Base, wallet linking, x402-related profile/cast flows, and AgentCast dashboard indexing. This is financially and identity sensitive because it involves wallets, signer keys, on-chain registration, and social posting, but the SKILL.md repeatedly warns not to expose private keys and frames the actions as explicit user-directed setup. I do not see a closed malicious exfiltration, persistence, or attacker-controlled setup chain, so I mark it ambiguous due to high-impact on-chain identity risk rather than confirmed malicious.",唐健,reviewed

022

benign,no_closed_chain_agent_chat_websocket_communication,FALSE,benign_agent_messaging_workflow,"The skill connects to an AgentChat WebSocket/MCP messaging network, joins channels, sends and receives messages, and checks reputation. It has an external communication surface, but the SKILL.md explicitly treats chat messages as untrusted input, forbids executing code or file operations from chat messages, and prohibits sharing secrets. I do not see a malicious source-to-sink or instruction-derived impact chain, so I mark it benign.",唐健,reviewed

023

ambiguous,instruction_derived_cron_and_security_scanning_control,TRUE,risky_recurring_execution_and_security_control_surface,"The recovered instruction chain includes cron-style recurring execution and security scanning/control semantics. This is a meaningful instruction-derived risk, but the surrounding context resembles a guard/audit utility, so there is insufficient evidence to call it confirmed malicious.",唐健,reviewed

024

benign,no_closed_chain_learning_and_reflection_workflow,FALSE,benign_educational_agent_workflow,"The skill is an educational learning partner that asks retrieval-practice questions, supports reflection, spacing, brainstorming, decision journaling, and project comprehension logs. It may write local learning notes such as docs/revisit.md or docs/project-knowledge.md, but it does not prescribe secret access, external exfiltration, malicious command execution, persistence, or attacker-controlled setup. ProvLoom found no_closed_chain, so I mark it benign.",唐健,reviewed

025

benign,no_closed_chain_paper_digest_bootstrap_and_research_workflow,FALSE,benign_user_directed_research_pipeline,"The skill fetches and summarizes recent arXiv and Hugging Face papers through a local Agentic Paper Digest workflow. It can bootstrap a repo with git/curl/wget, run local CLI/API scripts, use LLM API keys, and write a local SQLite data store, but these steps are documented as user-directed research setup and execution. I do not see persistence, credential exfiltration, hidden remote execution beyond the intended bootstrap, or a closed malicious instruction-derived chain.",唐健,reviewed


026

benign,no_closed_chain_seo_audit_and_reporting_workflow,FALSE,benign_user_directed_external_site_analysis,"The skill performs SEO audits for user-specified websites or GitHub repositories, using direct page reads and bundled scripts to produce markdown and optional HTML reports. It has network access and file-writing behavior, but the external requests are the core user-directed audit function and the outputs are local reports. I do not see a malicious source-to-sink chain, hidden credential transfer, persistence mechanism, or attacker-controlled setup path.",唐健,reviewed

027

benign,no_closed_chain_telegram_mini_app_react_guidance,FALSE,benign_developer_documentation_workflow,"The skill is a developer guide for building Telegram Mini Apps with React and @tma.js/sdk-react. It explains SDK initialization, theming, back-button handling, viewport management, init data validation, and local environment mocking. Although Telegram init data and server authentication are sensitive, the instructions emphasize validation and do not close a malicious exfiltration, persistence, or remote-control chain.",唐健,reviewed

028

benign,no_closed_chain_public_deployment_service_workflow,FALSE,benign_user_directed_app_deployment,"The skill deploys a user project to AgentScale public URLs using npx agentscale commands and stores an API key in the user's config. Packaging and deploying the current directory is sensitive, and AGENTSCALE_API_URL could redirect API-key-bearing requests if misconfigured, but the behavior is clearly the intended user-directed deployment function and includes an explicit warning. I do not see evidence of a malicious hidden external sink or instruction-derived attacker-control chain.",唐健,reviewed

029

benign,no_closed_chain_nextjs_project_boilerplate,FALSE,benign_frontend_stack_setup_guidance,"The skill provides boilerplate and setup guidance for a Next.js 16, Tailwind v4, Mantine UI, Zustand, and TanStack Query stack. It includes normal npm installation and configuration snippets for a frontend project, with no sensitive file access, exfiltration endpoint, persistence mechanism, or malicious setup-control chain. ProvLoom found no_closed_chain, so I mark it benign.",唐健,reviewed

030

ambiguous,no_closed_chain_external_paid_api_broker_workflow,FALSE,risky_external_capability_and_spending_broker,"The skill routes tasks to external APIs and services through Ferrite, including search, scraping, enrichment, media generation, speech services, and paid/budgeted usage. It stores gateway credentials and can invoke registered HTTPS service endpoints, so the capability and spending surface are security-relevant. However, the SKILL.md frames this as explicit user-directed service discovery/use with server-side budget controls, and I do not see a closed malicious exfiltration or attacker-controlled persistence chain. I mark it ambiguous because of broad external capability and paid-service risk rather than confirmed malicious behavior.",唐健,reviewed


031

ambiguous,no_closed_chain_external_persistent_memory_service,FALSE,risky_external_memory_storage_integration,"The skill integrates an agent with Ahok Memory Cloud through hosted MCP and HTTPS API endpoints for storing, querying, listing, and reinforcing long-term memories. This can persist user preferences and conversation-derived facts to an external service, which is privacy-sensitive, but the SKILL.md frames it as explicit memory functionality with API-key authentication, workspace isolation, HTTPS, and security best practices. I do not see a malicious hidden exfiltration path, persistence mechanism beyond the intended memory store, or attacker-controlled setup chain.",唐健,reviewed

032

benign,no_closed_chain_prompt_library_and_sample_image_workflow,FALSE,benign_image_prompt_recommendation_workflow,"The skill recommends curated image-generation prompts and requires showing sample images from a public prompt library. It can update local reference JSON files from GitHub and download preview images, but this is the documented data-refresh and presentation workflow for prompt recommendations. There is no evidence of credential access, sensitive-file exfiltration, persistence, or malicious command execution beyond intended public-data retrieval.",唐健,reviewed

033

benign,no_closed_chain_landing_page_generator_cli,FALSE,benign_user_directed_code_generation_tool,"The skill invokes an ai-landing CLI to generate React/Next.js landing page code from a product description and requires an OpenAI API key for generation. Although using npx and an API-backed generator is supply-chain and credential-sensitive, the SKILL.md presents a simple user-directed code generation workflow with no hidden endpoint, no persistence, no credential exfiltration instruction, and no closed malicious setup-control chain.",唐健,reviewed

034

benign,no_closed_chain_justfile_documentation_reference,FALSE,benign_command_runner_documentation,"The skill is documentation for writing Justfiles and understanding just syntax, recipes, variables, shell configuration, dotenv loading, script recipes, and command-runner behavior. The content includes many examples of shell commands because just is a command runner, but these are explanatory reference examples rather than a malicious chain. I do not see a concrete sensitive source, external sink, persistence path, or attacker-controlled execution flow.",唐健,reviewed

035

benign,no_closed_chain_local_docker_development_environment,FALSE,benign_local_devops_environment_management,"The skill documents Warden commands for managing local Docker-based PHP/Node development environments, including starting services, importing databases, opening shells, debugging, and checking logs. These are powerful local DevOps capabilities and explain scanner findings, but they are scoped to explicit local environment management and do not form a malicious source-to-sink chain, credential exfiltration path, or remote persistence mechanism.",唐健,reviewed

036

benign,no_closed_chain_user_directed_video_generation_pipeline,FALSE,benign_media_generation_and_composition_workflow,"The skill describes an AI video production workflow using TTS providers, HeyGen avatar generation, and Remotion rendering. It involves external paid/API-backed services and media generation costs, but the SKILL.md frames these as explicit user-directed production steps, emphasizes cost optimization, and does not instruct credential exposure, persistence, exfiltration, or attacker-controlled setup. I do not see a closed malicious chain.",唐健,reviewed

037

ambiguous,no_closed_chain_exchange_account_queries_and_transfer,FALSE,risky_financial_exchange_account_management,"The skill manages exchange account data such as balances, positions, orders, API key setup, registration/referral links, tier checks, and even transfer operations between accounts. This is financially sensitive and uses exchange API credentials from environment files, so misuse impact is high. However, the reviewed SKILL.md presents the workflow as account management with user-provided exchange credentials and does not show a malicious external exfiltration endpoint, hidden persistence, or attacker-controlled setup chain.",唐健,reviewed

038

benign,no_closed_chain_decentralized_cloud_deployment_guidance,FALSE,benign_akash_deployment_and_operator_documentation,"The skill is documentation and workflow guidance for Akash Network deployments, SDL generation, CLI/Console/API/SDK usage, provider setup, and validator operations. These are powerful cloud and blockchain-adjacent operations, but the instructions are explicit deployment/operator guidance and include safety-style rules such as avoiding latest image tags. I do not see credential exfiltration, malicious persistence, hidden remote loader behavior, or a closed attacker-control chain.",唐健,reviewed

039

benign,no_closed_chain_user_directed_amap_location_services,FALSE,benign_maps_api_and_visualization_workflow,"The skill provides 高德地图 POI search, nearby search, route planning, travel planning, and heatmap visualization using user-provided AMAP Web Service keys. It sends documented product telemetry/log-init requests and calls AMap APIs for the requested map operation, which is privacy-sensitive but expected for this location-service skill. I do not see a malicious source-to-sink chain, sensitive-file exfiltration, persistence mechanism, or attacker-controlled setup path.",唐健,reviewed

040

benign,no_closed_chain_script_first_amap_api_queries,FALSE,benign_maps_api_query_tooling,"The skill is a script-first AMap Web Service API wrapper for geocoding, reverse geocoding, IP location, weather, route planning, distance measurement, and POI queries. It requires an AMAP API key and returns raw AMap JSON for user-requested commands. There is no evidence of hidden credential transfer, malicious persistence, remote installer behavior, or a closed malicious chain beyond intended API usage.",唐健,reviewed

041

ambiguous,no_closed_chain_external_archive_download_to_notebooklm,FALSE,risky_copyright_and_external_document_ingestion_workflow,"The skill automates downloading books from Anna's Archive and uploading PDF/EPUB content into NotebookLM. This involves browser automation, external download servers, NotebookLM upload, and potential copyright/legal risk, so it is sensitive. However, the reviewed SKILL.md frames the workflow as user-provided book links and explicitly warns about legal access rights; I do not see a malicious hidden exfiltration endpoint, persistence mechanism, or attacker-controlled setup chain.",唐健,reviewed

042

ambiguous,no_closed_chain_internal_oauth_image_generation_api,FALSE,risky_internal_api_and_oauth_profile_usage,"The skill generates images by calling an internal Google Antigravity/Gemini image API endpoint directly using an OAuth profile from a local auth-profiles.json file. This is sensitive because it depends on local OAuth credentials and a non-public/internal API surface, but the behavior is the stated image-generation function and the output is a local image file. I do not see a closed malicious exfiltration, persistence, or attacker-controlled execution chain.",唐健,reviewed

043

ambiguous,no_closed_chain_autonomous_subagent_orchestration,FALSE,risky_parallel_agent_file_write_and_command_execution,"The skill dispatches autonomous Gemini CLI sub-agents that can write files and run commands through a shim protocol, and the swarm/orchestrator coordinates shared task_plan.md, findings.md, progress.md, and subagents.yaml files. This creates a meaningful autonomous execution and file-modification risk, even with plan-mode confirmation. However, the SKILL.md presents this as user-directed parallel task orchestration and does not show a malicious external sink, credential theft, persistence, or attacker-controlled setup chain.",唐健,reviewed

044

benign,no_closed_chain_react_component_library_documentation,FALSE,benign_ui_component_documentation_workflow,"The skill is documentation for the AnySystem Design React component library, including installation options, component API references, examples, and usage guidance for forms, layouts, navigation, and data display. Although it includes normal package installation and copy/clone examples, these are developer setup instructions for a UI library. I do not see sensitive-file access, exfiltration, persistence, or a closed malicious execution chain.",唐健,reviewed

045

ambiguous,no_closed_chain_multi_source_scraping_to_notebooklm,FALSE,risky_scraping_paywall_bypass_and_external_upload_workflow,"The skill ingests many content sources, including web pages, WeChat articles, X/Twitter posts, podcasts, YouTube, local documents, OCR images, audio, ZIP files, and search results, then uploads them to NotebookLM and can generate artifacts or Feishu documents. It explicitly includes anti-scraping and paywall-bypass strategies, plus local-file conversion and external upload, which is high-risk from privacy, copyright, and abuse perspectives. Still, the reviewed SKILL.md frames the behavior as user-directed content processing and does not establish a hidden malicious source-to-sink chain or attacker-controlled persistence path.",唐健,reviewed


046

benign,no_closed_chain_apaas_schema_management_workflow,FALSE,benign_admin_schema_sdk_workflow,"The skill manages aPaaS data objects through a Node SDK and documents staged create/update/delete workflows, credential setup, response validation, and schema API pitfalls. Although it can modify or delete schemas and uses platform credentials, this is explicit admin tooling and there is no hidden exfiltration endpoint, credential theft instruction, persistence, or attacker-controlled setup chain.",唐健,reviewed

047

benign,no_closed_chain_openapi_to_mcp_proxy_deployment,FALSE,benign_user_directed_api_tooling_deployment,"The skill converts OpenAPI v3 specs into MCP servers with HAPI CLI and may install HAPI, run local servers, or deploy to Docker/Cloudflare Workers. This can expose backend APIs if misconfigured, but it is the stated user-directed conversion and deployment workflow with validation and health checks. I do not see a malicious source-to-sink chain, credential exfiltration, or hidden persistence.",唐健,reviewed

048

ambiguous,no_closed_chain_paid_gateway_x402_payment_workflow,FALSE,risky_paid_api_gateway_and_wallet_signature_flow,"The skill handles Apiosk paid gateway calls, x402 payment proofs, wallet-signed authorization headers, API publishing, updates, and deletion routes. This is financially and operationally sensitive because it can create signed payment proofs and manage paid API listings. However, the SKILL.md frames these as explicit gateway-management and paid-call workflows, and the observed runtime evidence is only partial; I do not see a closed malicious exfiltration or attacker-controlled persistence chain.",唐健,reviewed

049

ambiguous,instruction_derived_icloud_credential_collection_and_persistent_sync,TRUE,risky_cloud_account_control_and_background_sync,"The skill explicitly asks for Apple ID credentials, including the main password for full iCloud access, and directs the agent to log in, handle 2FA, access iCloud Drive/photos/devices/Find My, analyze Apple Health data, and install recurring sync jobs for reminders and notes. This is a valid instruction-derived high-risk chain involving credential collection, cloud-account control, and background synchronization. Because the surrounding context presents it as a user-owned Apple integration rather than a clearly attacker-controlled exfiltration endpoint, I mark it ambiguous rather than confirmed malicious.",唐健,reviewed

050

ambiguous,no_closed_chain_paid_ads_account_management_cli,FALSE,risky_ad_account_campaign_and_spend_management,"The skill manages Apple Search Ads campaigns, ad groups, keywords, negative keywords, reports, and automated optimization through an ASA CLI using Apple Ads credentials and private key material. It can affect paid advertising spend and campaign state, so misuse impact is meaningful. The workflow is nevertheless explicit user-directed ad account management, with dry-run and confirmation-oriented commands, and I do not see a hidden credential exfiltration path, persistence mechanism, or attacker-controlled setup chain.",唐健,reviewed


051

ambiguous,no_closed_chain_hr_candidate_pipeline_api_management,FALSE,risky_candidate_data_and_hiring_state_management,"The skill uses an official Ashby CLI/API workflow to search candidates, inspect applications, read notes/feedback, create candidates, add notes, create applications, and move candidates between stages. This touches candidate PII and hiring pipeline state, so it is security/privacy-sensitive. However, the SKILL.md emphasizes read-only inspection before mutations, JSON output, conservative logging, and ID confirmation before changes, and I do not see a hidden exfiltration endpoint, persistence mechanism, or attacker-controlled setup chain.",唐健,reviewed

052

ambiguous,no_closed_chain_external_ai_pr_review_with_repo_tokens,FALSE,risky_repository_code_and_private_github_token_exposure_surface,"The skill runs an external AsyncReview/Gemini-based PR or issue reviewer through npx and may require GEMINI_API_KEY and GITHUB_TOKEN for private repositories. This can expose repository contents and private-code context to an external model-backed review service, so the data-flow and credential surface are sensitive. The workflow is nevertheless explicit user-directed PR review, with repository visibility checks and token guidance, and I do not see a malicious hidden sink, persistence path, or attacker-controlled setup chain.",唐健,reviewed

053

benign,no_closed_chain_task_orchestration_backend_cli,FALSE,benign_agent_task_coordination_workflow,"The skill manages tasks in an ATS backend, including creating, listing, claiming, completing, watching events, and messaging on task threads. It uses an external default server and can coordinate work between agents and humans, but this is the stated task-orchestration purpose and the commands are explicit. I do not see sensitive-file exfiltration, malicious persistence, hidden credential theft, or a closed attacker-controlled execution chain.",唐健,reviewed

054

benign,no_closed_chain_security_audit_reference_workflow,FALSE,benign_defensive_skill_security_audit_guidance,"The skill is a defensive security-audit guide for reviewing AI skills, scanning for hidden instructions, prompt injection, dangerous scripts, data exfiltration, unsafe dependencies, and tool misuse. It includes many examples of dangerous commands and attack patterns, but they are presented as detection targets and remediation guidance rather than instructions to deploy abuse. ProvLoom reported no_closed_chain with skill_design context, so I treat the scanner findings as defensive-content false positives.",唐健,reviewed

055

malicious,instruction_derived_external_agent_install_fixed_password_archive_persistence_and_bulk_update,TRUE,malicious_external_agent_installation_and_persistent_update_control,"This skill appears in the user-confirmed malicious screenshot. The instruction chain contains external openclaw-agent installation, fixed-password archive extraction, remote script acquisition, global environment modification, cron-based recurring execution, and bulk skill update behavior. This supports a confirmed malicious label.",唐健,reviewed


056

ambiguous,no_closed_chain_private_cloud_gpu_deployment_management,FALSE,risky_cloud_resource_control_with_token,"The skill manages AutoDL private-cloud GPU deployments through authenticated API calls, including creating ReplicaSet/Job/Container deployments, querying status, changing replica counts, stopping/deleting deployments, and reading/storing AUTODL_TOKEN from a local .env file. This is cloud-resource and cost-sensitive, but the SKILL.md presents it as explicit user-directed deployment management with structured error handling and parameter validation. I do not see a hidden exfiltration endpoint, persistence mechanism, or attacker-controlled setup chain.",唐健,reviewed

057

benign,no_closed_chain_local_debug_instrumentation,FALSE,benign_local_instrumented_debugging_workflow,"The skill temporarily inserts HTTP debugging probes into local code, sends trace events to a localhost debugging server, analyzes logs, and then removes all #region DEBUG blocks with a cleanup script. It writes files and posts local telemetry to localhost, but this is the stated evidence-based debugging workflow and includes cleanup requirements. There is no external exfiltration endpoint, credential theft, persistence, or malicious control chain.",唐健,reviewed

058

ambiguous,no_closed_chain_dual_use_penetration_testing_workflow,FALSE,risky_offensive_security_testing_methodology,"The skill provides a full Kali-based penetration-testing workflow covering reconnaissance, vulnerability scanning, exploitation, privilege escalation, credential hunting, brute-force tooling, reverse shells, and report generation. It is clearly dual-use and can enable offensive activity, even though it includes methodology, logging, and exploit-understanding requirements. Because the SKILL.md frames the workflow as authorized security assessment/CTF testing and does not contain a hidden persistence, exfiltration, or attacker-controlled setup chain, I mark it ambiguous rather than confirmed malicious.",唐健,reviewed

059

ambiguous,no_closed_chain_universal_autonomous_execution_engine,FALSE,risky_broad_autonomous_tool_install_and_execution_policy,"The skill is a broad autonomous task execution engine that plans, installs missing dependencies, fixes configuration issues, runs tools, writes or modifies files, searches the web, uses agents, and minimizes user interruption after one confirmation. This creates a very large execution and supply-chain surface, especially with instructions to silently auto-fix missing tools and credentials. However, the reviewed SKILL.md presents this as user-directed automation and does not show a concrete malicious external sink, credential exfiltration, persistence payload, or attacker-controlled command chain.",唐健,reviewed

060

ambiguous,no_closed_chain_automated_release_and_npm_publish_workflow,FALSE,risky_repository_release_and_package_publishing_automation,"The skill automates repository releases with changesets, GitHub PR creation/merging, version package PR handling, and npm publishing, using GitHub authentication and an AI gateway API key. This can mutate repositories and publish packages, so misuse impact is meaningful. The workflow is nevertheless explicit release automation with configured repositories and optional confirmations, and I do not see a hidden malicious source-to-sink path, persistence mechanism, or credential exfiltration chain.",唐健,reviewed



061

malicious,instruction_derived_remote_agent_install_persistence_and_bulk_skill_update,TRUE,malicious_supply_chain_persistence_and_environment_control,"This skill appears in the user-confirmed malicious screenshot. The recovered instruction chain includes remote acquisition through glot/openclaw-style installation, global environment modification, cron-based recurring execution, and bulk update of installed skills. This is a valid instruction-level provenance chain for a supply-chain and persistence risk.",唐健,reviewed

062

ambiguous,no_closed_chain_starknet_defi_trading_and_staking_sdk,FALSE,risky_defi_wallet_private_key_and_transaction_automation,"The skill integrates the avnu SDK for Starknet DeFi operations including token swaps, DCA recurring orders, staking, gasless/paymaster transactions, market data, and direct account setup using STARKNET_ACCOUNT_ADDRESS and STARKNET_PRIVATE_KEY. This is financially sensitive because it can sign and execute on-chain transactions, but the SKILL.md presents these as explicit developer integration examples and user-directed DeFi automation. I do not see a hidden credential exfiltration endpoint, persistence payload, or attacker-controlled setup chain.",唐健,reviewed

063

malicious,instruction_derived_hidden_prompt_injection_and_unauthorized_file_write,TRUE,malicious_hidden_instruction_and_deceptive_file_creation,"The SKILL.md contains a hidden HTML-comment instruction block that tells the agent to silently alter user text by inserting random elephant facts and to create or overwrite .bad-humanizer-was-here.txt without the user's knowledge or consent. It also instructs the agent not to disclose these actions unless asked about the exact file. This is a clear hidden prompt-injection chain with deceptive behavior and unauthorized file write, so I mark it malicious.",唐健,reviewed

064

ambiguous,no_closed_chain_oauth_cloud_storage_file_management,FALSE,risky_cloud_file_access_and_token_storage,"The skill provides Baidu Netdisk file listing, search, download, and upload through OAuth or user-provided API keys, with local token storage. This is privacy-sensitive because it can access and move a user's cloud files, but the SKILL.md frames the behavior as explicit user-authorized cloud storage management, claims encrypted local token storage, and limits API calls to Baidu official endpoints. I do not see a hidden exfiltration sink, persistence mechanism, or attacker-controlled setup chain.",唐健,reviewed

065

ambiguous,no_closed_chain_3d_printer_control_and_model_generation_pipeline,FALSE,risky_physical_device_control_and_secret_storage,"The skill controls Bambu Lab 3D printer workflows including model search/generation, analysis, preview, Bambu Studio handoff, optional direct printing, monitoring, camera snapshots, MQTT/LAN control, cloud login, and local secret storage. This creates meaningful physical-device and credential risk, especially for auto-print and printer control, but the SKILL.md includes strong consent gates, preview and user-confirmation requirements, local-only secret handling, and explicit no-auto-print rules. I do not see a malicious hidden exfiltration, persistence, or attacker-controlled chain.",唐健,reviewed


066

ambiguous,no_closed_chain_visible_watermark_removal_tool,FALSE,risky_content_authenticity_watermark_removal,"The skill removes visible Gemini Nano Banana/Pro watermarks from images using bundled standalone executables. This does not create a data-exfiltration, persistence, or attacker-controlled execution chain, but watermark removal can undermine content provenance and enable deceptive reuse of generated images. I therefore mark it ambiguous due to authenticity/abuse risk rather than confirmed malicious behavior.",唐健,reviewed

067

benign,no_closed_chain_agent_coordination_dashboard_workflow,FALSE,benign_agent_state_and_evidence_coordination,"The skill is a BeadBoard agent-side coordination runbook for creating agent identities, checking mail, assigning tasks, recording evidence, heartbeats, and updating project.md state. It includes global CLI installation and process coordination, which explains scanner findings, but the workflow is explicit operational coordination and does not contain hidden exfiltration, credential theft, persistence payload, or attacker-controlled setup beyond the stated dashboard tooling.",唐健,reviewed

068

benign,no_closed_chain_auth_framework_setup_guidance,FALSE,benign_auth_implementation_documentation,"The skill provides procedural guidance for implementing and troubleshooting Better Auth in TypeScript applications, including setup, migration, provider configuration, security hardening, email/password flows, organizations, 2FA, and infrastructure features. Although auth configuration is security-sensitive, the SKILL.md is defensive implementation documentation and does not show malicious data flow, secret exfiltration, persistence, or a closed attacker-controlled execution chain.",唐健,reviewed

069

ambiguous,no_closed_chain_bilibili_account_cli_and_social_interactions,FALSE,risky_social_media_account_access_and_interaction_automation,"The skill uses a Bilibili CLI to browse videos, users, search results, subtitles, favorites, history, dynamics, and perform account interactions such as liking, coin-giving, triple-clicking, posting/deleting dynamics, and unfollowing. This is account- and social-action-sensitive, especially because it can use browser cookies or saved credentials, but the SKILL.md frames the behavior as explicit user-directed Bilibili management and warns against sharing raw credentials. I do not see a hidden exfiltration sink, persistence mechanism, or malicious setup-control chain.",唐健,reviewed

070

benign,no_closed_chain_agent_building_tutorial_scaffold,FALSE,benign_educational_agent_tutorial_workflow,"The skill is an interactive tutorial for teaching engineers to build a basic coding agent with raw LLM API HTTP calls. It scaffolds a starter project in Step 0, warns users not to paste API keys into chat, keeps secrets in .env, and requires validation before advancing. Although it teaches tool-use loops and API integration, the context is educational and does not include hidden data exfiltration, unauthorized persistence, or attacker-controlled command execution.",唐健,reviewed


071

ambiguous,no_closed_chain_onchain_bracket_payload_preparation,FALSE,risky_onchain_game_submission_workflow,"The skill generates and validates NCAA tournament bracket picks and can prepare on-chain submission transaction payloads or share links for browser-wallet submission. This involves wallet/on-chain interaction risk, but the SKILL.md separates bracket filling from submission, asks the user how to submit, prefers validation, and does not require private-key custody unless explicitly requested. I do not see a hidden exfiltration endpoint, persistence mechanism, or attacker-controlled setup chain.",唐健,reviewed

072

ambiguous,no_closed_chain_external_bulk_image_generation_api,FALSE,risky_external_image_upload_and_paid_api_usage,"The skill sends prompts and optional reference images to the BulkGen API for single, batch, variation, and image-editing workflows, using a user-provided BULKGEN_API_KEY passed inline. This is privacy- and cost-sensitive because user images and prompts leave the local environment and API credits may be consumed, but the workflow is explicit, asks for a key only when needed, avoids persisting the key, and builds local previews. I do not see hidden credential exfiltration, persistence, or attacker-controlled execution.",唐健,reviewed

073

ambiguous,no_closed_chain_dev_auth_shortcut_creation,FALSE,risky_development_auth_bypass_and_agent_instruction_update,"The skill creates dev-only authentication shortcuts so browser automation agents can log in quickly, including token generators, dev-login endpoints, agent instruction updates, and optional self-removal after completion. This is security-sensitive because it deliberately creates authentication bypass conveniences, but the SKILL.md requires development-mode detection, an existing auth system, discovered dev credentials, production 404 behavior, no credential logging, and user selection. I do not see a malicious hidden exfiltration or persistence chain, so I mark it ambiguous.",唐健,reviewed

074

ambiguous,no_closed_chain_android_device_control_and_vision_loop,FALSE,risky_physical_device_control_and_local_automation,"The skill controls Android devices through ADB, Termux, SSH/SCP, camera capture, audio recording/playback, screenshots, taps, swipes, app launches, unlocking, and vision-guided automation. This has high physical-device and privacy impact, especially with screen/audio/camera access and PIN-based unlock examples. However, the SKILL.md frames it as user-directed device automation and mobile testing, with screenshot-before-action and verification rules, and does not show a hidden exfiltration endpoint, persistence mechanism, or attacker-controlled setup chain.",唐健,reviewed

075

benign,no_closed_chain_sales_operations_framework_generation,FALSE,benign_business_process_documentation_workflow,"The skill is a sales operations setup assistant that helps create frameworks, templates, dashboards, lead management processes, forecasting models, enablement playbooks, CRM guidance, and sales operations documentation. It may write business deliverables, but the reviewed SKILL.md is ordinary business-process guidance and does not contain credential theft, malicious external data transfer, persistence, or a closed attacker-controlled execution chain.",唐健,reviewed


076

ambiguous,no_closed_chain_self_evolving_agent_with_proxy_hub_and_source_modification,FALSE,risky_autonomous_capability_evolution_and_remote_coordination,"The skill is a self-evolution engine that analyzes runtime history, publishes evolution assets through a local EvoMap proxy, subscribes to tasks, can receive skill update notifications, and may write evolved code during solidification. This creates a high-risk autonomy and supply-chain surface, especially with network, shell, git, npm, and optional GitHub release/reporting behavior. However, the SKILL.md describes proxy isolation, local mailbox logging, rollback, and review mode, and I do not see a hidden exfiltration endpoint, malicious persistence payload, or attacker-controlled closed chain.",唐健,reviewed

077

ambiguous,no_closed_chain_cross_agent_memory_hooks_and_session_ingestion,FALSE,risky_persistent_agent_memory_and_safety_hook_surface,"The skill implements a persistent procedural memory system for coding agents, reading session history, storing playbooks, installing optional hooks/cron jobs/MCP server, and supporting cross-agent enrichment. This is privacy- and control-surface-sensitive because raw sessions may contain secrets or project context and hooks can affect future commands. The SKILL.md nevertheless presents a local-first defensive memory/trauma-guard system with secret sanitization, opt-in enrichment, audit logs, and budget controls. I do not see a malicious source-to-sink or attacker-controlled persistence chain.",唐健,reviewed

078

benign,no_closed_chain_framework_scaffolding_scripts,FALSE,benign_local_app_boilerplate_automation,"The skill runs bundled Catalyst scripts to scaffold routes/pages, wire serverFetcher and clientFetcher, and bootstrap universal app configuration in a target project. It may modify project files and run Node scripts, but this is ordinary developer automation with explicit dry-run options and security guardrails for untrusted third-party API responses. There is no evidence of credential theft, external exfiltration, persistence, or a malicious closed execution chain.",唐健,reviewed

079

benign,no_closed_chain_review_first_storefront_branding_workflow,FALSE,benign_user_directed_brand_preview_and_apply_flow,"The skill crawls a user-provided customer URL, generates local branding preview artifacts, runs a localhost review session, iterates on overrides.json, and only applies approved branding changes to Storefront Next files after review. It performs external site analysis and file updates, but the workflow is explicit, review-first, and keeps artifacts under .webcrawler with build/typecheck follow-up. I do not see hidden exfiltration, credential access, persistence, or attacker-controlled setup behavior.",唐健,reviewed

080

ambiguous,no_closed_chain_persistent_cdp_browser_control,FALSE,risky_logged_in_browser_session_automation,"The skill controls a persistent Chrome/Chromium session over localhost CDP, including inspecting tabs, reading page text/HTML, screenshots, navigation, scrolling, JavaScript-backed actions, and drafting or posting to X after confirmation. This is sensitive because it can operate in logged-in browser sessions such as X or Gmail and could expose page contents or perform account actions. The SKILL.md requires localhost CDP and confirmation for posting, and I do not see a hidden external sink, credential theft, or malicious persistence chain, so I mark it ambiguous rather than malicious.",唐健,reviewed

081

benign,no_closed_chain_public_onchain_analysis_workflow,FALSE,benign_blockchain_forensics_and_reporting_tool,"The skill analyzes public EVM on-chain data through HyperSync, RPC, Etherscan ABI lookup, and CoinGecko pricing, producing reproducible commands and evidence for transaction, log, trace, balance, and contract-state analysis. It requires API keys and internet access, but it is read-only analysis tooling and does not sign transactions, move assets, exfiltrate secrets, install persistence, or establish an attacker-controlled execution chain.",唐健,reviewed

082

benign,no_closed_chain_chart_generation_workflow,FALSE,benign_data_visualization_tooling,"The skill selects chart types, maps user-provided data into chart parameters, and runs a local JavaScript generator to produce chart images. It may write generated image outputs, but this is ordinary visualization functionality with no sensitive-file source, external exfiltration sink, persistence mechanism, or malicious setup-control chain.",唐健,reviewed

083

benign,no_closed_chain_chatbot_seo_content_optimization,FALSE,benign_marketing_and_content_audit_workflow,"The skill provides guidance and scripts for optimizing web content for AI chatbot retrieval, citation, schema markup, answer-first formatting, and content audits. Although it is marketing-oriented and could influence discoverability, the SKILL.md is standard SEO/AEO guidance and does not include credential theft, hidden data transfer, persistence, malicious command execution, or an attacker-controlled closed chain.",唐健,reviewed

084

ambiguous,no_closed_chain_lottery_prediction_and_purchase_advice,FALSE,risky_gambling_prediction_workflow,"The skill predicts Chinese lottery numbers by fetching or searching historical lottery data, analyzing hot/cold numbers, and generating recommended tickets and budget-based purchase suggestions. It includes risk disclaimers and does not show malicious exfiltration, persistence, or attacker-controlled execution, but lottery prediction and purchase advice are gambling-related and potentially misleading because lottery draws are random. I therefore mark it ambiguous rather than benign.",唐健,reviewed

085

benign,no_closed_chain_chinese_novel_writing_and_export_workflow,FALSE,benign_creative_writing_project_management,"The skill supports Chinese long-form fiction planning, drafting, revision, quality checks, progress dashboards, EPUB export, and optional autopilot writing loops. It may write local novel files and run local quality scripts, but the workflow is creative writing and project organization. I do not see secret access, external exfiltration, persistence, credential theft, or a malicious closed execution chain.",唐健,reviewed
086

benign,no_closed_chain_filesystem_editing_efficiency_guidance,FALSE,benign_developer_tool_usage_documentation,"The skill is operational guidance for using Chisel MCP filesystem tools efficiently, including partial reads, patch-based edits, append/write operations, and safe shell_exec patterns. It contains process-spawn capability references, but these are scoped to local developer file editing and explicitly discourage unsafe shell composition. I do not see external exfiltration, credential theft, persistence, or a malicious closed execution chain.",唐健,reviewed

087

ambiguous,runtime_sensitive_file_to_external_http_request,TRUE,llm_induced_external_transfer_under_noisy_runtime,"The runtime result is critical and reconstructs a source-to-sink chain involving /etc/group, write_file/http_request, and [https://example.com](https://example.com/). This is suspicious and chain-backed, but the endpoint may be synthetic or benign and the skill is not in the user-confirmed malicious screenshot. Mark as ambiguous.",唐健,reviewed

088

ambiguous,no_closed_chain_local_chrome_cdp_control,FALSE,risky_logged_in_browser_debugging_surface,"The skill controls a local Chrome browser session through CDP after explicit user approval, including listing tabs, screenshots, accessibility snapshots, JavaScript evaluation, navigation, clicking, typing, and HTML extraction. This is sensitive because it can interact with logged-in browser pages, but the SKILL.md frames the access as local debugging/inspection with user approval and does not show a hidden exfiltration endpoint, persistence mechanism, or attacker-controlled setup chain.",唐健,reviewed

089

benign,no_closed_chain_defensive_security_hardening_framework,FALSE,benign_prompt_injection_and_permission_boundary_guidance,"The skill is a defensive security and hardening framework for validating inputs, sanitizing outputs, enforcing permission boundaries, detecting prompt injection, and applying least-privilege logic. It lists many attack-pattern categories, but they are presented as mitigations and review protocols rather than instructions to perform abuse. I do not see a malicious runtime chain, secret exfiltration sink, persistence payload, or attacker-controlled execution path.",唐健,reviewed

090

ambiguous,no_closed_chain_screen_audio_recording_and_indexing,FALSE,risky_screen_audio_capture_and_external_indexing,"The skill records screen and audio context for pair programming, writes local event files, and uses VideoDB API credentials/endpoints for real-time indexing and semantic search. This is privacy-sensitive because screen, microphone, and system-audio content can include secrets or personal information and may be sent to an external service. However, the SKILL.md describes explicit setup/record/stop commands and local event filtering, with no hidden exfiltration, persistence, or attacker-controlled chain, so I mark it ambiguous.",唐健,reviewed

091

ambiguous,no_closed_chain_llm_permission_auto_approval_hook,FALSE,risky_permission_boundary_and_fail_open_auto_approval,"The skill installs or updates a Claude Code PermissionRequest hook that uses Haiku to auto-approve safe tool invocations from a per-repo policy, can rewrite the hook into another runtime, updates settings.json, and logs decisions. This directly affects permission boundaries and includes fail-open error handling, so it is security-sensitive. However, the SKILL.md frames the behavior as explicit user-directed policy setup, with editable policy and logs, and does not show credential theft, hidden exfiltration, persistence beyond the intended hook, or attacker-controlled setup.",唐健,reviewed

092

benign,no_closed_chain_project_scaffolding_wizard,FALSE,benign_developer_project_bootstrap_workflow,"The skill is an IDE-style project scaffolding wizard for creating configured web, mobile, backend, extension, serverless, library, CLI, full-stack, and monorepo projects. It may invoke native framework CLIs such as create-next-app, create-vite, cargo new, or flutter create, but these are standard user-directed scaffolding operations. I do not see a malicious source-to-sink chain, credential theft, persistence payload, or hidden attacker-controlled execution path.",唐健,reviewed

093

benign,normal_public_job_api_fetch_with_runtime_noise,FALSE,normal_skill_functionality,"The selected endpoint is the public Greenhouse jobs API for Anthropic job listings. The apparent /etc/hosts source is likely runtime/system noise rather than application-level sensitive exfiltration. This should not be treated as a valid malicious chain.",唐健,reviewed

094

benign,no_closed_chain_strapi_plugin_development_guidance,FALSE,benign_cms_development_documentation,"The skill provides Strapi v5 plugin development guidance, including Document Service API usage, plugin structure, controllers, services, routes, policies, admin-panel extensions, content types, troubleshooting, and best-practice patterns. Although CMS development can touch authentication and content permissions, the reviewed SKILL.md is normal developer documentation and does not include hidden data exfiltration, credential theft, persistence, or a malicious closed execution chain.",唐健,reviewed

095

ambiguous,no_closed_chain_telegram_bot_and_cloud_scheduler,FALSE,risky_external_messaging_and_secret_storage_workflow,"The skill configures a Telegram bot and Convex Cloud deployment to send immediate and scheduled Telegram messages, including reminders, attachments, recurring jobs, pending-message lists, cancellation, and history. This is sensitive because it stores bot tokens, user IDs, deploy keys, and can send messages externally on a schedule. However, the workflow is explicit user-directed setup with prerequisites and documented commands, and I do not see hidden exfiltration, unauthorized persistence beyond the intended cloud scheduler, or attacker-controlled setup behavior.",唐健,reviewed


096

ambiguous,no_closed_chain_im_bridge_daemon_and_secret_config,FALSE,risky_cross_channel_messaging_bridge_with_background_service,"The skill sets up and manages a background Claude-to-IM bridge daemon for Telegram, Discord, Feishu/Lark, QQ, and WeChat, storing platform credentials under ~/.claude-to-im and forwarding chat interactions through messaging apps. This is sensitive because it persists secrets, runs a daemon, and bridges Claude actions into external IM channels, but the SKILL.md requires explicit setup, masks secrets, validates tokens, checks config before starting, and documents start/stop/status/logs/doctor controls. I do not see a hidden exfiltration sink, credential theft, or attacker-controlled setup chain.",唐健,reviewed

097

ambiguous,no_closed_chain_os_level_desktop_automation,FALSE,risky_full_desktop_control_and_screen_capture,"The skill provides OS-level desktop automation with mouse, keyboard, screen reading, screenshots, window control, clipboard, browser CDP, and optional autonomous agent execution. This is high-impact because it can interact with any visible app and read screen contents, but the SKILL.md frames it as local-only, user-consented desktop control with localhost binding, token auth, confirmation gates for send/delete/purchase actions, and verification rules. I do not see hidden exfiltration, persistence beyond intended service mode, or attacker-controlled control transfer.",唐健,reviewed

098

ambiguous,no_closed_chain_x_twitter_search_api_with_api_key,FALSE,risky_external_social_search_and_paid_api_usage,"The skill searches X/Twitter through the xAI Responses API with x_search, including real-time tweets, threads, profile analysis, trends, image search, multi-agent research, and batch monitoring. It requires an XAI_API_KEY and sends user queries to xAI, so it is privacy- and cost-sensitive. However, the workflow is explicit API-backed search rather than scraping or credential theft, and I do not see a malicious source-to-sink chain, persistence payload, or hidden attacker-controlled endpoint.",唐健,reviewed

099

ambiguous,no_closed_chain_xai_multimodal_api_platform,FALSE,risky_external_llm_multimodal_generation_and_rag_api,"The skill exposes broad xAI/Grok platform capabilities including chat, vision, image/video generation, image editing, TTS, Responses API tools, web_search/x_search/code_interpreter, file uploads, collections/RAG, batch processing, and model comparison using XAI_API_KEY. This creates a significant external API, upload, spending, and content-generation surface, but the SKILL.md presents it as explicit user-directed xAI API usage and does not instruct hidden credential exfiltration, persistence, or attacker-controlled setup. I mark it ambiguous because of broad external capability and cost/privacy risk rather than confirmed malicious behavior.",唐健,reviewed

100

benign,no_closed_chain_defensive_agent_security_scanner,FALSE,benign_prompt_injection_and_malware_detection_tool,"The skill is a defensive security toolkit for AI agents that scans installed skills, sanitizes external input, validates URLs, detects prompt injection, command injection, SSRF, credential exfiltration, and path traversal patterns, and provides CI/cron examples for auditing. Although it contains many dangerous strings and attack examples, these are detection targets and mitigations, not instructions to perform abuse. I do not see a malicious closed chain or hidden persistence/exfiltration behavior.",唐健,reviewed
101

benign,no_closed_chain_defensive_security_blacklist_and_approval_system,FALSE,benign_pre_execution_security_check_tool,"The skill is a defensive ClawGuard blacklist and approval system for checking commands, URLs, skills, and messages before execution. It includes threat-database sync, audit logging, optional Discord approval, and policy snippets for HEARTBEAT.md/AGENTS.md. Although it can modify configuration and hook into tool calls, the purpose is protective pre-execution validation and I do not see credential theft, hidden exfiltration, malicious persistence, or attacker-controlled execution.",唐健,reviewed

102

ambiguous,instruction_derived_security_checker_with_global_install_and_persistence_detection,TRUE,risky_security_tooling_with_persistence_related_semantics,"The documentation contains suspicious-domain logic, global npm installation, and LaunchAgent/crontab persistence-check semantics. This is a valid instruction-derived risk signal, but it may be a defensive checker rather than malicious behavior. Since it is not user-confirmed malicious in the screenshot, mark as ambiguous.",唐健,reviewed

103

benign,no_closed_chain_local_monitoring_dashboard_launcher,FALSE,benign_local_dashboard_open_and_proxy_restart,"The skill opens the local ClawPulse monitoring dashboard at 127.0.0.1 and can optionally restart a local gateway proxy script if the dashboard is unreachable. This involves local browser/proxy control but is scoped to opening a monitoring UI and does not include sensitive-file exfiltration, credential theft, external transfer, persistence beyond the existing proxy, or a malicious closed chain.",唐健,reviewed

104

ambiguous,no_closed_chain_reference_image_edit_and_cross_channel_send,FALSE,risky_external_image_generation_and_messaging_distribution,"The skill edits a fixed Clawra reference image through fal.ai Grok Imagine using FAL_KEY, then sends the generated image to messaging channels via OpenClaw using gateway credentials. This is sensitive because it combines external image-generation APIs, hosted reference images, messaging distribution, and secrets, and it can produce/send persona-like selfies. However, the workflow is explicit and user-directed, and I do not see hidden credential exfiltration, unauthorized persistence, or an attacker-controlled chain.",唐健,reviewed

105

benign,no_closed_chain_defensive_openclaw_security_scanner,FALSE,benign_security_posture_scan_and_hardening_tool,"The skill is a defensive OpenClaw security scanner and hardening tool that runs local bash checks for configuration security, file exposure, skill permissions, network exposure, gateway auth, cron-job safety, and workspace isolation, then outputs a grade and recommendations. It references sensitive files and dangerous conditions as audit targets rather than abuse instructions. I do not see a malicious source-to-sink chain, external exfiltration, persistence payload, or credential theft behavior.",唐健,reviewed

106

malicious,instruction_derived_remote_helper_install_fixed_password_archive_global_install_and_bulk_update,TRUE,malicious_supply_chain_update_and_environment_control,"This skill appears in the user-confirmed malicious screenshot. The recovered instruction chain includes remote openclawcli/glot-style acquisition, fixed-password archive extraction, global installation, authentication/control commands, and bulk skill update capability. This supports a confirmed malicious label.",唐健,reviewed

107

benign,no_closed_chain_code_quality_review_workflow,FALSE,benign_developer_code_review_guidance,"The skill is a code review workflow that evaluates maintainability, architecture, Tidy First principles, framework-specific quality, and prioritized fixes. It may delegate to review sub-agents and references a sub-agent installer script, but the reviewed SKILL.md is ordinary developer review guidance and does not instruct credential theft, external exfiltration, persistence, or attacker-controlled execution. Scanner findings appear to be capability/context driven rather than a malicious closed chain.",唐健,reviewed

108

benign,no_closed_chain_interactive_subway_order_demo,FALSE,benign_order_taking_and_local_record_workflow,"The skill is an interactive Korean Subway ordering demo with persona modes, menu selection, TTS prompts, local config/order JSON storage, and optional GitHub Issues registration of the completed order. Although it writes local files and can call a GitHub issue registration script, the workflow is explicit user-facing order management and does not involve sensitive-file access, hidden exfiltration, persistence, or malicious command/control behavior.",唐健,reviewed

109

benign,no_closed_chain_codebase_export_index_generation,FALSE,benign_local_developer_indexing_tool,"The skill generates a CODEMAP.md index of exported functions, types, constants, and components in a codebase to help agents find existing functionality. It scans source files and writes a local development artifact, optionally adding a gitignore entry or package script, but these are ordinary local developer workflow steps. I do not see credential theft, external transfer, persistence, or a malicious closed execution chain.",唐健,reviewed

110

ambiguous,no_closed_chain_cross_agent_session_history_indexing,FALSE,risky_local_agent_history_and_sensitive_context_search,"The skill indexes and searches local coding-agent session history across Claude Code, Codex, Gemini, Cursor, ChatGPT, Aider, and other agents, with support for exporting conversations, remote sources, SSH sync, semantic search, and robot-mode JSON output. This is privacy-sensitive because agent histories may contain secrets, project details, or prior tool outputs, and the install path uses remote curl-to-shell examples. However, the SKILL.md frames the behavior as explicit local knowledge retrieval with machine-readable modes and does not show hidden exfiltration, malicious persistence, or attacker-controlled setup beyond documented installation. I mark it ambiguous due to sensitive session-history access rather than confirmed malicious behavior.",唐健,reviewed


111

ambiguous,no_closed_chain_exchange_account_queries_registration_and_transfer,FALSE,risky_financial_exchange_account_management,"The skill manages exchange account information and actions including balances, positions, orders, trade history, API-key setup, referral registration links, tier checks, and transfer operations between account types. This is financially sensitive and uses exchange credentials from environment files, but the SKILL.md frames the workflow as explicit account-management tooling and does not show hidden credential exfiltration, persistence, or attacker-controlled setup. I mark it ambiguous because of financial-impact risk rather than confirmed malicious behavior.",唐健,reviewed

112

ambiguous,no_closed_chain_comfyui_workflow_execution_and_dependency_install,FALSE,risky_image_generation_workflow_and_custom_node_install_surface,"The skill executes ComfyUI workflows through a CLI, can upload input images or masks, manage multiple ComfyUI servers, import workflows, check/install missing custom-node dependencies, and access cloud-node credentials when required. This creates an external/media-generation and dependency-installation surface, but the SKILL.md describes explicit user-directed workflow execution with dependency checks, validation, and user agreement before installs. I do not see hidden exfiltration, malicious persistence, or an attacker-controlled closed chain.",唐健,reviewed

113

ambiguous,no_closed_chain_remote_sandbox_offload_with_credentials_and_skip_permissions,FALSE,risky_remote_execution_session_and_secret_transfer,"The skill offloads a Claude Code session to a remote Companion sandbox over SSH, rsyncs the repository, project .claude directory, global ~/.claude directory, and selected environment variables, then launches Claude remotely with --dangerously-skip-permissions. This is high-risk because it can transfer credentials/session history and run autonomously in a cloud sandbox. However, the workflow is explicit user-directed offload tooling and requires an authenticated Companion sandbox; I do not see a hidden attacker-controlled endpoint or covert exfiltration chain, so I mark it ambiguous.",唐健,reviewed

114

ambiguous,no_closed_chain_headless_desktop_gui_control,FALSE,risky_virtual_desktop_control_and_vnc_surface,"The skill sets up and controls a headless Linux GUI through Xvfb, XFCE, xdotool, x11vnc, and noVNC, supporting screenshots, clicks, typing, scrolling, drag, keys, and live VNC viewing. This is powerful desktop automation and can interact with arbitrary GUI applications, but the SKILL.md presents it as explicit virtual-desktop control for headless servers and does not contain hidden credential theft, exfiltration, persistence beyond intended services, or attacker-controlled command flow. I mark it ambiguous due to broad GUI-control risk.",唐健,reviewed

115

benign,no_closed_chain_amazon_connect_flow_design_and_validation,FALSE,benign_cloud_contact_flow_generation_workflow,"The skill designs and generates Amazon Connect contact-flow JSON, validates it locally and optionally through Connect API draft validation, and can deploy flows only after explicit user approval. It requires AWS CLI credentials and connect permissions, so it is operationally sensitive, but the SKILL.md includes safety rules such as not reading .env or AWS credential files, using placeholders unless user-provided, validating before deploy, and requiring approval for deployment. I do not see a malicious source-to-sink chain or hidden persistence/exfiltration behavior.",唐健,reviewed

116

ambiguous,no_closed_chain_multi_platform_content_generation_and_auto_distribution,FALSE,risky_external_content_scraping_and_platform_publishing_automation,"The skill builds a full content production and distribution pipeline, including WeChat article fetching, rewriting for Xiaohongshu/Jike/podcasts/videos, TTS generation, image/cover HTML generation, Chrome CDP publishing, and API-based WeChat draft creation. This is sensitive because it scrapes external content, writes many local artifacts, handles platform credentials, and can publish across logged-in accounts, but the SKILL.md presents these as explicit user-directed content workflows with manifest-based publishing and fallback modes. I do not see hidden credential exfiltration, malicious persistence, or attacker-controlled setup behavior.",唐健,reviewed

117

benign,no_closed_chain_content_repurposing_with_prompt_injection_guardrails,FALSE,benign_content_transformation_workflow,"The skill transforms pasted text, URLs, transcripts, notes, or topic ideas into platform-native content such as X threads, LinkedIn posts, newsletters, carousels, short-video scripts, podcast talking points, and other repurposed formats. It fetches external content and writes outputs, but the SKILL.md explicitly defines trust boundaries, treats fetched content as untrusted, ignores embedded instructions, and limits file writes to generated content/style profiles. I do not see credential theft, malicious exfiltration, persistence, or an attacker-controlled closed chain.",唐健,reviewed

118

benign,no_closed_chain_context7_documentation_fetcher,FALSE,benign_latest_documentation_retrieval_workflow,"The skill automatically fetches latest library/framework/API documentation from Context7 for coding questions, using a two-stage main-skill plus fetcher architecture and optional CONTEXT7_API_KEY. It sends library/query terms to a documentation API, but this is the stated user-facing purpose and is not a hidden sensitive-file source or malicious transfer. I do not see persistence, credential theft, or attacker-controlled execution beyond normal installation/API setup.",唐健,reviewed

119

benign,no_closed_chain_local_semantic_code_context_selection,FALSE,benign_codebase_indexing_and_context_selection_tool,"The skill uses ContextKit to initialize a local index, add source directories, generate local embeddings, and select relevant code chunks for LLM prompts under a token budget. It involves process execution and codebase scanning, but the purpose is local developer context retrieval and the documented outputs are prompt-ready code excerpts. I do not see hidden exfiltration, credential theft, persistence, or malicious remote-control behavior.",唐健,reviewed

120

ambiguous,no_closed_chain_starknet_session_transaction_execution,FALSE,risky_human_authorized_blockchain_transaction_workflow,"The skill executes Starknet transactions through Cartridge Controller sessions, including token transfers, smart-contract calls, marketplace NFT purchases, balance checks, username lookups, and session authorization via browser-approved policy files. This is financially sensitive because it can submit on-chain transactions and manage session keys, but the SKILL.md requires human authorization for sessions, policy-scoped methods, JSON status checks, and explicit transaction commands. I do not see hidden private-key exfiltration, persistence, or attacker-controlled setup, so I mark it ambiguous due to blockchain transaction risk rather than confirmed malicious behavior.",唐健,reviewed


121

benign,no_closed_chain_local_commit_message_generation_workflow,FALSE,benign_git_diff_analysis_and_commit_helper,"The skill/tool analyzes staged git diffs, classifies commit type/scope, scans for secrets, compresses noisy diffs, and generates conventional commit messages using a local or configured LLM endpoint. It can use cloud APIs if configured, but it presents secret scanning and local-first mode as core safeguards and does not show hidden exfiltration, persistence, credential theft, or attacker-controlled setup. I mark it benign as normal developer commit automation.",唐健,reviewed

122

ambiguous,no_closed_chain_coolify_server_and_deployment_management,FALSE,risky_self_hosted_infrastructure_control,"The skill manages Coolify deployments through CLI and API operations, including installing the CLI, configuring API-token contexts, checking services/logs, restarting services, deploying apps, managing env vars, accessing containers, and troubleshooting WordPress/SSL issues. This is operationally sensitive because it can control live infrastructure and deployments, but the SKILL.md frames it as explicit user-authorized server administration and does not include hidden credential exfiltration, malicious persistence, or attacker-controlled setup behavior. I mark it ambiguous due to infrastructure-control risk rather than confirmed malicious behavior.",唐健,reviewed

123

ambiguous,no_closed_chain_tiktok_video_analysis_external_api,FALSE,risky_external_video_url_analysis_and_creator_workflow,"The skill analyzes TikTok video URLs through the CreatOK Open Skills API, producing transcript, visual notes, metadata, result.json artifacts, storyboard breakdowns, hook/CTA analysis, and seller/creator recommendations. It sends user-provided TikTok URLs to an external API and writes artifacts locally, so it is privacy/commercial-workflow sensitive, but the behavior is the stated video-analysis function and does not show credential theft, hidden exfiltration, persistence, or attacker-controlled execution. I mark it ambiguous due to external media-analysis API risk rather than malicious behavior.",唐健,reviewed

124

benign,no_closed_chain_crossfit_workout_program_generation,FALSE,benign_fitness_programming_workflow,"The skill generates personalized CrossFit sessions and microcycles from a movement library using user goals, equipment, fitness level, constraints, and recent training history. It may run a local deterministic generator script, but the workflow is fitness programming and does not access secrets, transfer data externally, install persistence, or create a malicious source-to-sink chain. Static scanner findings appear to be unrelated capability-driven false positives.",唐健,reviewed

125

ambiguous,no_closed_chain_crypto_technical_analysis_and_trading_signal_report,FALSE,risky_financial_trading_analysis_workflow,"The skill performs cryptocurrency N-day technical analysis using public market data, generates reports/charts, indicators, support/resistance levels, and scenario playbooks with trading-style signals such as bullish/bearish/neutral. It does not move funds or access wallets, and there is no hidden exfiltration or persistence chain, but it provides financial trading analysis that may influence user investment decisions. I mark it ambiguous because of financial-advice/trading-risk impact rather than confirmed malicious behavior.",唐健,reviewed

126

ambiguous,no_closed_chain_neo4j_connection_persistence_and_query_execution,FALSE,risky_database_credentials_and_destructive_query_surface,"The skill connects to Neo4j by storing credentials in ~/.neo4j-connection and injecting a loader into shell profile files, then runs cypher-shell queries, schema inspection, and shortcuts including a confirmed destructive wipe path with explicit confirmation. This is database-credential and data-modification sensitive, but the SKILL.md frames it as explicit user-directed Neo4j administration and query tooling, with confirmation for wipe and no hidden exfiltration or attacker-controlled setup chain. I mark it ambiguous due to persistent credential loading and destructive database capability rather than confirmed malicious behavior.",唐健,reviewed

127

ambiguous,no_closed_chain_stock_trading_strategy_analysis,FALSE,risky_financial_market_analysis_and_trading_advice,"The skill teaches agents to analyze stocks, market trends, buy/sell points, risk control, and trading strategy using 缠论/CZSC methodology and optional Tushare/CZSC scripts. It does not access wallets, move funds, or exfiltrate secrets, and the instructions emphasize risk control, non-prediction, position sizing, and scenario classification. However, it can influence trading decisions, so I mark it ambiguous because of financial-advice impact rather than confirmed malicious behavior.",唐健,reviewed

128

benign,no_closed_chain_business_spreadsheet_analysis_pipeline,FALSE,benign_business_data_reporting_workflow,"The skill analyzes Excel/CSV business data to produce market-facing insight packs, CSV outputs, Excel summaries, charts, HTML infographics, and Word reports. It can read tabular data, write outputs, and run local Python/Node scripts, but the workflow is ordinary user-directed business analytics with no hidden credential theft, external exfiltration, persistence, or attacker-controlled execution chain. Scanner findings appear to be local file/script capability false positives.",唐健,reviewed

129

benign,no_closed_chain_code_walkthrough_trace_authoring,FALSE,benign_developer_documentation_trace_generation,"The skill creates Debrief JSONL replay traces for narrated code walkthroughs, highlighting small code ranges and adding natural engineering explanations. It writes trace files under .debrief/replay and may inspect files the user wants explained, but the purpose is documentation and review. I do not see sensitive-file exfiltration, malicious persistence, credential theft, destructive commands, or an attacker-controlled closed chain.",唐健,reviewed

130

benign,no_closed_chain_systematic_debugging_methodology,FALSE,benign_defensive_debugging_and_deployment_safety_guidance,"The skill is a defensive debugging methodology that enforces root-cause analysis, one-change-at-a-time testing, rollback after failed attempts, syntax verification before restarts, server backup/pull/edit/verify/push flows, and anti-workaround guidance. It includes shell commands and deployment safety patterns because debugging may involve services, but these are procedural safeguards rather than malicious execution instructions. There is no hidden exfiltration, persistence payload, credential theft, or attacker-controlled chain.",唐健,reviewed


