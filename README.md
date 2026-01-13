# 🔐 Secure Role-Based Multi-Tenant Web Application

A production-style **multi-tenant backend system** built using **Django REST Framework**, implementing **JWT authentication**, **Role-Based Access Control (RBAC)**, and **organization-level data isolation**.

This project is inspired by real-world **SaaS backend architectures** and focuses on **security, scalability, and clean authorization design**.

---

## 🚀 Key Features

- Email-based JWT Authentication
- Role-Based Access Control (RBAC)
  - **SUPER_ADMIN** – Platform-level access
  - **ORG_ADMIN** – Organization-level access
- Multi-Tenant Architecture (Organization Isolation)
- Secure User Management APIs
- Organization Management APIs
- Audit Logging for API actions
- Production-style permission handling
- Clean, modular Django project structure

---

## 🧠 User Roles & Access

| Role | Permissions |
|-----|------------|
| SUPER_ADMIN | Manage all organizations and users |
| ORG_ADMIN | Manage users within own organization |

---

## 🏗 System Architecture (Overview)

- Stateless authentication using **JWT**
- Shared database with **tenant isolation**
- Permission-first request handling
- Queryset-level data filtering
- Clean separation of concerns

> This design mirrors how real SaaS platforms enforce security and access control.

---

## 🛠 Tech Stack

- **Python**
- **Django**
- **Django REST Framework**
- **JWT (SimpleJWT)**
- **RBAC (Custom Permission Classes)**
- **SQLite / PostgreSQL**
- RESTful API Design

---

## ⚙️ Project Setup

### 1️⃣ Clone Repository
```bash
git clone https://github.com/Arya-9989/secure-multi-tenant-platform.git
cd secure-multi-tenant-platform
