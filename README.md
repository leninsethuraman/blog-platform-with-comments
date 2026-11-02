# Blog Platform with Comments

Full-stack blog: Express + SQLite + JWT auth, with a vanilla JS frontend.

## Run
```
npm install
JWT_SECRET=your-secret npm start    # http://localhost:3000
```

## REST API
| Method | Endpoint | Auth | Purpose |
|---|---|---|---|
| POST | /api/auth/register | – | Create account |
| POST | /api/auth/login | – | Log in, returns JWT |
| GET | /api/auth/me | ✔ | Current user |
| GET | /api/posts | – | List posts |
| GET | /api/posts/:id | – | Post with comments |
| POST | /api/posts | ✔ | Create post |
| PUT | /api/posts/:id | owner | Edit post |
| DELETE | /api/posts/:id | owner | Delete post |
| POST | /api/posts/:id/comments | ✔ | Add comment |
| DELETE | /api/comments/:id | comment or post owner | Delete comment |

Tables: `users`, `posts`, `comments` (foreign keys, cascade delete).
