# 🛡️ KeyRunes — Modern Access Control Engine in Rust

**KeyRunes** is a high-performance, extensible authorization system designed to compete with and surpass traditional solutions like Keycloak. It brings together advanced access control models such as **RBAC**, **ABAC**, **ReBAC**, and **PBAC**, while offering a great developer experience and enterprise-grade scalability.

> ⚙️ Built for Rust. Inspired by RPG systems. Designed for security-critical platforms.

---

## 🚀 Key Features

### 🔐 Advanced Authorization Models

- **RBAC** (Role-Based Access Control): Global (realm) and per-client roles, including role composition.
- **ABAC** (Attribute-Based Access Control): Policies based on dynamic user/environment attributes (e.g. time, department, device).
- **ReBAC** (Relationship-Based Access Control): Authorization through graph-based relationships (e.g. ownership, collaboration).
- **PBAC** (Policy-Based Access Control): Combine RBAC + ABAC in unified policies.

### 📈 Scalability & Performance

- Lightweight **Policy Decision Point (PDP)** with <10ms latency at enterprise scale.
- Optional in-process or external microservice deployment.
- Distributed cache support to reduce calls to external sources (e.g. Keycloak/LDAP).

### 👨‍💻 Developer Experience

- **Policy-as-Code** using YAML or Rego, versionable via Git.
- CI/CD-ready: Run automated tests for policies.
- Simulate access decisions before deployment with a rich UI.
- SDKs (planned) for Rust, Java, Go, and Python for seamless integration.

### 📊 Audit & Compliance

- Complete decision logs with metadata (timestamp, policy, attributes).
- Automated rollback for failed policies in production.
- Compliance reports for standards like HIPAA and PCI.

### 🔌 Integration & Extensibility

- Federate identities from Keycloak, Okta and others via OIDC.
- Map custom IdP attributes into policies.
- Webhook support for access denial events.
- Plugin system for sourcing attributes from internal systems (CRM, HR).

### 🏢 Multi-Tenant Support

- Isolated policies and data per tenant.
- Delegated administration (e.g. department leads managing roles).

### 💡 Real-World Use Cases

- Hospitals (HIPAA): Role + location + shift access to medical records.
- Banks: Enforce MFA outside corporate network.
- E-commerce: Temporary supplier access.
- IoT: Device-based publish/subscribe permissions.

---

## 📦 Roadmap (Milestones)

| Phase | Focus |
|-------|-------|
| MVP   | RBAC, Policy-as-Code, SDKs, Keycloak integration |
| V1    | ABAC, ReBAC, Simulators, Attribute Graphs |
| V2    | Multi-tenancy, Audit, Compliance tooling |
| V3    | Edge-case handling, IoT, Delegated access UI |

---

## 🧪 Quickstart (WIP)

> ⚠️ The implementation is still in progress. A `quickstart` guide will be available once the core engine is ready.

---

## 📂 Project Structure (Planned)

/src
/core # Policy engine
/models # Roles, attributes, relationships
/parser # Policy-as-code parser (YAML/Rego)
/sdk # API bindings
/tests
/docs


---

## 🤝 Contributing

Contributions are welcome! If you’re interested in:
- Access control systems
- Graph-based security
- High-performance Rust services

…then feel free to open issues, suggest ideas, or contribute code once we’re live 🚀

---

## 📄 License

[MIT](LICENSE)

---

## 🧙‍♂️ About the Name

Just like magical runes control access to forbidden realms in fantasy worlds, **KeyRunes** grants or denies access to sensitive resources — through logic, context, and relationships.

> 🔒 **Security meets storytelling.**
