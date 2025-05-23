# SvelteKit Security Best Practices: Comprehensive Guide

Security is paramount when building web applications. SvelteKit provides several built-in security features, but understanding how to implement them properly and adding additional security layers is crucial for protecting your application and users. This comprehensive guide covers all aspects of SvelteKit security.

## Table of Contents

1. [Authentication and Authorization](#authentication-and-authorization)
2. [CSRF Protection](#csrf-protection)
3. [Content Security Policy (CSP)](#content-security-policy-csp)
4. [XSS Prevention](#xss-prevention)
5. [Input Validation and Sanitization](#input-validation-and-sanitization)
6. [Security Headers](#security-headers)
7. [Session Management](#session-management)
8. [Server-Side Security](#server-side-security)
9. [Deployment Security](#deployment-security)
10. [Security Testing and Monitoring](#security-testing-and-monitoring)

## Authentication and Authorization

### Modern Authentication with SvelteKitAuth

**Installation and Setup**
```bash
npm install @auth/sveltekit
```

**Basic Configuration**
```javascript
// src/hooks.server.js
import { SvelteKitAuth } from '@auth/sveltekit'
import { redirect } from '@sveltejs/kit'
import Google from '@auth/sveltekit/providers/google'
import GitHub from '@auth/sveltekit/providers/github'

export const handle = SvelteKitAuth({
  providers: [
    Google({ 
      clientId: GOOGLE_CLIENT_ID, 
      clientSecret: GOOGLE_CLIENT_SECRET 
    }),
    GitHub({ 
      clientId: GITHUB_CLIENT_ID, 
      clientSecret: GITHUB_CLIENT_SECRET 
    })
  ],
  callbacks: {
    async jwt({ token, user, account }) {
      // Persist the OAuth access_token to the token right after signin
      if (account) {
        token.accessToken = account.access_token
        token.refreshToken = account.refresh_token
      }
      return token
    },
    async session({ session, token }) {
      // Send properties to the client
      session.accessToken = token.accessToken
      return session
    }
  },
  session: {
    strategy: 'jwt',
    maxAge: 30 * 24 * 60 * 60, // 30 days
  },
  cookies: {
    sessionToken: {
      name: `next-auth.session-token`,
      options: {
        httpOnly: true,
        sameSite: 'lax',
        path: '/',
        secure: true // Set to true in production
      }
    }
  }
})
```

### Route Protection Strategy

**Server-Side Route Protection**
```javascript
// src/routes/protected/+layout.server.js
import { redirect } from '@sveltejs/kit'

export async function load({ locals }) {
  const session = await locals.getSession()
  
  if (!session?.user) {
    throw redirect(303, '/auth/signin')
  }
  
  return {
    session
  }
}
```

**Middleware-Based Protection**
```javascript
// src/hooks.server.js
import { sequence } from '@sveltejs/kit/hooks'

const authorization = async ({ event, resolve }) => {
  // Protect admin routes
  if (event.url.pathname.startsWith('/admin')) {
    const session = await event.locals.getSession()
    if (!session?.user?.role === 'admin') {
      throw redirect(303, '/unauthorized')
    }
  }
  
  // Protect API routes
  if (event.url.pathname.startsWith('/api/protected')) {
    const session = await event.locals.getSession()
    if (!session?.user) {
      return new Response('Unauthorized', { status: 401 })
    }
  }
  
  return resolve(event)
}

export const handle = sequence(SvelteKitAuth(authConfig), authorization)
```

**Avoiding Load Function Security Pitfalls**

❌ **Don't do this** - Security checks in layout load functions can be bypassed:
```javascript
// ❌ INSECURE - Can be bypassed by parallel execution
// src/routes/projects/+layout.server.js
export async function load({ locals }) {
  const user = locals.user
  if (!user || !['manager', 'developer'].includes(user.role)) {
    throw error(403, 'Unauthorized')
  }
  // This protection can be bypassed!
}
```

✅ **Do this** - Use hooks for comprehensive protection:
```javascript
// ✅ SECURE - Cannot be bypassed
// src/hooks.server.js
const authGuard = async ({ event, resolve }) => {
  if (event.url.pathname.startsWith('/projects')) {
    const user = event.locals.user
    if (!user || !['manager', 'developer'].includes(user.role)) {
      throw redirect(303, '/unauthorized')
    }
  }
  return resolve(event)
}
```

## CSRF Protection

### Understanding SvelteKit's Built-in CSRF Protection

SvelteKit includes automatic CSRF protection that:
- Validates origin headers for state-changing requests (POST, PUT, PATCH, DELETE)
- Blocks cross-origin form submissions by default
- Protects against most CSRF attacks automatically

**Built-in Protection Configuration**
```javascript
// svelte.config.js
const config = {
  kit: {
    csrf: {
      checkOrigin: true, // Default: true
    }
  }
}
```

### Custom CSRF Protection Implementation

For more granular control, implement custom CSRF protection:

```javascript
// src/lib/hooks/csrf.js
import { error, json, text } from '@sveltejs/kit'

/**
 * Custom CSRF protection middleware
 * @param {string[]} allowedPaths - Paths that bypass CSRF protection
 * @param {string[]} allowedOrigins - Trusted origins for cross-origin requests
 */
export function csrf(allowedPaths = [], allowedOrigins = []) {
  return async ({ event, resolve }) => {
    const { request, url } = event
    const requestOrigin = request.headers.get('origin')
    const isSameOrigin = requestOrigin === url.origin
    const isAllowedOrigin = allowedOrigins.includes(requestOrigin ?? '')
    const isAllowedPath = allowedPaths.includes(url.pathname)
    
    // Check if this is a potentially dangerous request
    const isDangerousMethod = ['POST', 'PUT', 'PATCH', 'DELETE'].includes(request.method)
    const isFormSubmission = isFormContentType(request)
    
    if (isDangerousMethod && isFormSubmission && !isSameOrigin && !isAllowedOrigin && !isAllowedPath) {
      const csrfError = error(403, `Cross-site ${request.method} form submissions are forbidden`)
      
      if (request.headers.get('accept') === 'application/json') {
        return json(csrfError.body, { status: csrfError.status })
      }
      return text(csrfError.body.message, { status: csrfError.status })
    }
    
    return resolve(event)
  }
}

function isFormContentType(request) {
  const contentType = request.headers.get('content-type')?.split(';', 1)[0].trim() ?? ''
  return [
    'application/x-www-form-urlencoded',
    'multipart/form-data',
    'text/plain'
  ].includes(contentType.toLowerCase())
}
```

**Usage in hooks.server.js**
```javascript
// src/hooks.server.js
import { sequence } from '@sveltejs/kit/hooks'
import { csrf } from './lib/hooks/csrf.js'

const allowedPaths = ['/api/public', '/webhooks/stripe']
const allowedOrigins = ['https://trusted-partner.com']

export const handle = sequence(
  csrf(allowedPaths, allowedOrigins),
  // ... other handlers
)
```

### CSRF Token Implementation

For additional security, implement CSRF tokens:

```javascript
// src/lib/server/csrf.js
import { randomBytes } from 'crypto'

export function generateCSRFToken() {
  return randomBytes(32).toString('hex')
}

export function validateCSRFToken(sessionToken, formToken) {
  return sessionToken && formToken && sessionToken === formToken
}
```

```javascript
// src/routes/+layout.server.js
import { generateCSRFToken } from '$lib/server/csrf.js'

export async function load({ locals }) {
  const csrfToken = generateCSRFToken()
  locals.csrfToken = csrfToken
  
  return {
    csrfToken
  }
}
```

```svelte
<!-- src/routes/contact/+page.svelte -->
<script>
  export let data
</script>

<form method="POST" action="?/submit">
  <input type="hidden" name="csrf_token" value={data.csrfToken} />
  <input type="email" name="email" required />
  <button type="submit">Submit</button>
</form>
```

## Content Security Policy (CSP)

### Automatic CSP Configuration

SvelteKit can automatically generate CSP headers:

```javascript
// svelte.config.js
const config = {
  kit: {
    csp: {
      mode: 'auto', // 'hash' | 'nonce' | 'auto'
      directives: {
        'default-src': ['self'],
        'script-src': ['self'],
        'style-src': ['self', 'unsafe-inline'],
        'img-src': ['self', 'data:', 'https:'],
        'font-src': ['self'],
        'connect-src': ['self'],
        'frame-ancestors': ['none'],
        'base-uri': ['self'],
        'form-action': ['self']
      },
      reportOnly: {
        'script-src': ['self'],
        'report-uri': ['/api/csp-report']
      }
    }
  }
}
```

### Advanced CSP Configuration

**Separate CSP Configuration File**
```javascript
// csp-config.js
export const cspDirectives = {
  'default-src': ['self'],
  'script-src': [
    'self',
    'unsafe-eval', // Only if absolutely necessary
    'https://cdn.jsdelivr.net',
    'https://unpkg.com'
  ],
  'style-src': [
    'self',
    'unsafe-inline', // Required for Svelte components
    'https://fonts.googleapis.com'
  ],
  'img-src': [
    'self',
    'data:',
    'https:',
    'blob:'
  ],
  'font-src': [
    'self',
    'https://fonts.gstatic.com'
  ],
  'connect-src': [
    'self',
    'https://api.example.com',
    'wss://ws.example.com'
  ],
  'media-src': ['self'],
  'object-src': ['none'],
  'frame-ancestors': ['none'],
  'base-uri': ['self'],
  'form-action': ['self'],
  'upgrade-insecure-requests': true
}

export const cspReportOnly = {
  'script-src': ['self', 'report-sample'],
  'report-uri': ['/api/csp-violations'],
  'report-to': ['csp-endpoint']
}
```

**CSP Violation Reporting**
```javascript
// src/routes/api/csp-violations/+server.js
import { json } from '@sveltejs/kit'

export async function POST({ request }) {
  try {
    const violation = await request.json()
    
    // Log violation (use your preferred logging service)
    console.error('CSP Violation:', {
      timestamp: new Date().toISOString(),
      documentUri: violation['document-uri'],
      violatedDirective: violation['violated-directive'],
      blockedUri: violation['blocked-uri'],
      userAgent: request.headers.get('user-agent')
    })
    
    // Send to external monitoring service (Sentry, LogRocket, etc.)
    // await sendToMonitoringService(violation)
    
    return json({ received: true })
  } catch (error) {
    console.error('Error processing CSP violation:', error)
    return json({ error: 'Failed to process violation' }, { status: 400 })
  }
}
```

### CSP for Static Sites

**Generate CSP Headers for Static Deployment**
```javascript
// scripts/generate-csp-headers.js
import fs from 'fs'
import path from 'path'
import { parse } from 'node-html-parser'

function extractCSPFromHTML(filePath) {
  const html = fs.readFileSync(filePath, 'utf-8')
  const root = parse(html)
  const cspMeta = root.querySelector('meta[http-equiv="content-security-policy"]')
  
  if (cspMeta) {
    return cspMeta.getAttribute('content')
  }
  return null
}

function generateHeadersFile() {
  const buildDir = './build'
  const cspValues = new Set()
  
  // Extract CSP from all HTML files
  function walkDirectory(dir) {
    const files = fs.readdirSync(dir)
    
    files.forEach(file => {
      const filePath = path.join(dir, file)
      const stat = fs.statSync(filePath)
      
      if (stat.isDirectory()) {
        walkDirectory(filePath)
      } else if (file.endsWith('.html')) {
        const csp = extractCSPFromHTML(filePath)
        if (csp) cspValues.add(csp)
      }
    })
  }
  
  walkDirectory(buildDir)
  
  // Generate _headers file for Netlify/Cloudflare Pages
  const headersContent = `/*
  Content-Security-Policy: ${Array.from(cspValues)[0] || 'default-src \'self\''}
  X-Frame-Options: DENY
  X-Content-Type-Options: nosniff
  Referrer-Policy: strict-origin-when-cross-origin
  Permissions-Policy: camera=(), microphone=(), geolocation=()
`
  
  fs.writeFileSync(path.join(buildDir, '_headers'), headersContent)
  console.log('Generated _headers file for static deployment')
}

generateHeadersFile()
```

## XSS Prevention

### Safe HTML Rendering

**Avoid @html when possible**
```svelte
<!-- ❌ Dangerous - Never trust user input -->
<div>{@html userContent}</div>

<!-- ✅ Safe - Automatic escaping -->
<div>{userContent}</div>
```

**When you must use @html, sanitize first**
```javascript
// Install sanitization library
// npm install dompurify
// npm install -D @types/dompurify

// src/lib/utils/sanitize.js
import DOMPurify from 'dompurify'
import { JSDOM } from 'jsdom'

const window = new JSDOM('').window
const purify = DOMPurify(window)

export function sanitizeHTML(html) {
  return purify.sanitize(html, {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a', 'p', 'br'],
    ALLOWED_ATTR: ['href'],
    ALLOW_DATA_ATTR: false
  })
}
```

```svelte
<!-- Safe HTML rendering -->
<script>
  import { sanitizeHTML } from '$lib/utils/sanitize.js'
  
  export let userContent
  $: safeHTML = sanitizeHTML(userContent)
</script>

<div>{@html safeHTML}</div>
```

### Component-Level XSS Prevention

**Safe Link Component**
```svelte
<!-- src/lib/components/SafeLink.svelte -->
<script>
  export let href = ''
  export let target = '_self'
  
  // Validate and sanitize href
  $: safeHref = validateURL(href)
  
  function validateURL(url) {
    try {
      const parsed = new URL(url, window.location.origin)
      
      // Only allow http, https, and mailto protocols
      if (!['http:', 'https:', 'mailto:'].includes(parsed.protocol)) {
        return '#'
      }
      
      return parsed.href
    } catch {
      return '#'
    }
  }
</script>

<a href={safeHref} {target} rel={target === '_blank' ? 'noopener noreferrer' : undefined}>
  <slot />
</a>
```

**Safe Image Component**
```svelte
<!-- src/lib/components/SafeImage.svelte -->
<script>
  export let src = ''
  export let alt = ''
  
  $: safeSrc = validateImageURL(src)
  
  function validateImageURL(url) {
    try {
      const parsed = new URL(url, window.location.origin)
      
      // Only allow http and https for images
      if (!['http:', 'https:', 'data:'].includes(parsed.protocol)) {
        return '/placeholder.jpg'
      }
      
      return parsed.href
    } catch {
      return '/placeholder.jpg'
    }
  }
</script>

<img src={safeSrc} {alt} on:error={() => safeSrc = '/placeholder.jpg'} />
```

## Input Validation and Sanitization

### Server-Side Validation

**Form Action Validation**
```javascript
// src/routes/contact/+page.server.js
import { fail } from '@sveltejs/kit'
import { z } from 'zod'

const contactSchema = z.object({
  name: z.string()
    .min(1, 'Name is required')
    .max(100, 'Name too long')
    .regex(/^[a-zA-Z\s]+$/, 'Name contains invalid characters'),
  email: z.string()
    .email('Invalid email address')
    .max(255, 'Email too long'),
  message: z.string()
    .min(10, 'Message must be at least 10 characters')
    .max(1000, 'Message too long')
})

export const actions = {
  default: async ({ request }) => {
    const formData = await request.formData()
    const data = Object.fromEntries(formData)
    
    try {
      // Validate input
      const validatedData = contactSchema.parse(data)
      
      // Additional sanitization
      const sanitizedData = {
        name: sanitizeText(validatedData.name),
        email: validatedData.email.toLowerCase().trim(),
        message: sanitizeText(validatedData.message)
      }
      
      // Process the safe data
      await processContactForm(sanitizedData)
      
      return { success: true }
    } catch (error) {
      if (error instanceof z.ZodError) {
        const fieldErrors = error.errors.reduce((acc, err) => {
          acc[err.path[0]] = err.message
          return acc
        }, {})
        
        return fail(400, { errors: fieldErrors, data })
      }
      
      return fail(500, { error: 'Server error' })
    }
  }
}

function sanitizeText(text) {
  return text
    .trim()
    .replace(/[<>]/g, '') // Remove potential HTML tags
    .replace(/javascript:/gi, '') // Remove javascript: protocol
    .replace(/on\w+=/gi, '') // Remove event handlers
}
```

### API Endpoint Validation

```javascript
// src/routes/api/users/+server.js
import { json, error } from '@sveltejs/kit'
import { z } from 'zod'

const userSchema = z.object({
  username: z.string()
    .min(3, 'Username must be at least 3 characters')
    .max(20, 'Username must be less than 20 characters')
    .regex(/^[a-zA-Z0-9_]+$/, 'Username can only contain letters, numbers, and underscores'),
  email: z.string().email('Invalid email format'),
  age: z.number().int().min(13).max(120).optional()
})

export async function POST({ request }) {
  try {
    const data = await request.json()
    
    // Validate input
    const validatedData = userSchema.parse(data)
    
    // Check rate limiting
    const clientIP = request.headers.get('x-forwarded-for') || 'unknown'
    if (await isRateLimited(clientIP)) {
      throw error(429, 'Too many requests')
    }
    
    // Additional business logic validation
    if (await userExists(validatedData.email)) {
      throw error(409, 'User already exists')
    }
    
    const user = await createUser(validatedData)
    
    return json({ success: true, userId: user.id })
  } catch (err) {
    if (err instanceof z.ZodError) {
      throw error(400, { message: 'Validation failed', errors: err.errors })
    }
    throw err
  }
}
```

### Rate Limiting Implementation

```javascript
// src/lib/server/rateLimit.js
const requestCounts = new Map()

export function createRateLimit(options = {}) {
  const {
    windowMs = 15 * 60 * 1000, // 15 minutes
    max = 100, // requests per window
    keyGenerator = (request) => request.headers.get('x-forwarded-for') || 'unknown'
  } = options
  
  return (request) => {
    const key = keyGenerator(request)
    const now = Date.now()
    const windowStart = now - windowMs
    
    // Clean old entries
    for (const [k, timestamps] of requestCounts.entries()) {
      const filtered = timestamps.filter(t => t > windowStart)
      if (filtered.length === 0) {
        requestCounts.delete(k)
      } else {
        requestCounts.set(k, filtered)
      }
    }
    
    // Check current requests
    const timestamps = requestCounts.get(key) || []
    const recentRequests = timestamps.filter(t => t > windowStart)
    
    if (recentRequests.length >= max) {
      return false // Rate limited
    }
    
    // Add current request
    recentRequests.push(now)
    requestCounts.set(key, recentRequests)
    
    return true // Allowed
  }
}
```

## Security Headers

### Comprehensive Security Headers Implementation

```javascript
// src/hooks.server.js
import type { Handle } from '@sveltejs/kit'

const securityHeaders = {
  // Prevent the page from being embedded in frames
  'X-Frame-Options': 'DENY',
  
  // Prevent MIME type sniffing
  'X-Content-Type-Options': 'nosniff',
  
  // Control referrer information
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  
  // HSTS - Force HTTPS
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
  
  // Disable XSS filtering (modern browsers have better CSP)
  'X-XSS-Protection': '0',
  
  // Control browser features
  'Permissions-Policy': [
    'camera=()',
    'microphone=()',
    'geolocation=()',
    'payment=()',
    'usb=()',
    'accelerometer=()',
    'gyroscope=()',
    'magnetometer=()'
  ].join(', '),
  
  // Cross-origin policies
  'Cross-Origin-Embedder-Policy': 'require-corp',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Resource-Policy': 'same-origin',
  
  // Prevent DNS prefetching
  'X-DNS-Prefetch-Control': 'off',
  
  // Prevent download of dangerous files
  'X-Download-Options': 'noopen',
  
  // Prevent cross-domain policies
  'X-Permitted-Cross-Domain-Policies': 'none',
  
  // Origin agent cluster
  'Origin-Agent-Cluster': '?1'
}

export const handle: Handle = async ({ event, resolve }) => {
  const response = await resolve(event)
  
  // Apply security headers
  Object.entries(securityHeaders).forEach(([header, value]) => {
    response.headers.set(header, value)
  })
  
  // Environment-specific headers
  if (process.env.NODE_ENV === 'production') {
    response.headers.set('Server', '') // Hide server information
  }
  
  return response
}
```

### Environment-Specific Security

```javascript
// src/lib/server/security.js
export function getSecurityConfig(environment) {
  const baseConfig = {
    'X-Frame-Options': 'DENY',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'strict-origin-when-cross-origin'
  }
  
  switch (environment) {
    case 'production':
      return {
        ...baseConfig,
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
        'Content-Security-Policy': 'default-src \'self\'; script-src \'self\' \'sha256-...\'',
        'Server': '' // Hide server info
      }
      
    case 'development':
      return {
        ...baseConfig,
        // Relaxed CSP for development
        'Content-Security-Policy-Report-Only': 'default-src \'self\' \'unsafe-inline\' \'unsafe-eval\''
      }
      
    default:
      return baseConfig
  }
}
```

## Session Management

### Secure Session Configuration

```javascript
// src/lib/server/session.js
import jwt from 'jsonwebtoken'
import { dev } from '$app/environment'

const SESSION_CONFIG = {
  secret: process.env.SESSION_SECRET,
  maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
  httpOnly: true,
  secure: !dev,
  sameSite: 'lax',
  path: '/'
}

export function createSession(user) {
  const payload = {
    userId: user.id,
    email: user.email,
    role: user.role,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + (7 * 24 * 60 * 60) // 7 days
  }
  
  return jwt.sign(payload, SESSION_CONFIG.secret)
}

export function verifySession(token) {
  try {
    return jwt.verify(token, SESSION_CONFIG.secret)
  } catch {
    return null
  }
}

export function createSecureCookie(name, value, options = {}) {
  return {
    name,
    value,
    options: {
      ...SESSION_CONFIG,
      ...options
    }
  }
}
```

### Session Validation Middleware

```javascript
// src/hooks.server.js
import { verifySession } from '$lib/server/session.js'

export const handle = async ({ event, resolve }) => {
  // Extract session from cookie
  const sessionToken = event.cookies.get('session')
  
  if (sessionToken) {
    const session = verifySession(sessionToken)
    
    if (session) {
      // Validate session hasn't expired
      if (session.exp * 1000 > Date.now()) {
        event.locals.user = {
          id: session.userId,
          email: session.email,
          role: session.role
        }
        
        // Refresh session if it's close to expiring
        const timeUntilExpiry = (session.exp * 1000) - Date.now()
        if (timeUntilExpiry < 24 * 60 * 60 * 1000) { // Less than 24 hours
          const newToken = createSession(event.locals.user)
          event.cookies.set('session', newToken, SESSION_CONFIG)
        }
      } else {
        // Session expired, clear cookie
        event.cookies.delete('session', { path: '/' })
      }
    }
  }
  
  return resolve(event)
}
```

## Server-Side Security

### Environment Variables Security

**Proper Environment Variable Management**
```javascript
// src/lib/server/env.js
import { env } from '$env/dynamic/private'

// Validate required environment variables
const requiredEnvVars = [
  'DATABASE_URL',
  'SESSION_SECRET',
  'JWT_SECRET'
]

export function validateEnvironment() {
  const missing = requiredEnvVars.filter(key => !env[key])
  
  if (missing.length > 0) {
    throw new Error(`Missing required environment variables: ${missing.join(', ')}`)
  }
  
  // Validate sensitive values
  if (env.SESSION_SECRET && env.SESSION_SECRET.length < 32) {
    throw new Error('SESSION_SECRET must be at least 32 characters long')
  }
}

// Safe environment variable access
export function getEnv(key, defaultValue = undefined) {
  const value = env[key]
  
  if (value === undefined && defaultValue === undefined) {
    throw new Error(`Environment variable ${key} is not set`)
  }
  
  return value || defaultValue
}
```

### Database Security

**Safe Database Queries**
```javascript
// src/lib/server/database.js
import { db } from './db.js'

// ❌ Vulnerable to SQL injection
export async function getUserUnsafe(email) {
  return db.query(`SELECT * FROM users WHERE email = '${email}'`)
}

// ✅ Safe parameterized query
export async function getUserSafe(email) {
  return db.query('SELECT id, email, name, role FROM users WHERE email = ?', [email])
}

// ✅ Input validation + safe query
export async function getUserValidated(email) {
  // Validate input
  if (!email || typeof email !== 'string' || !isValidEmail(email)) {
    throw new Error('Invalid email address')
  }
  
  // Use parameterized query
  const users = await db.query(
    'SELECT id, email, name, role, created_at FROM users WHERE email = ? AND active = 1',
    [email.toLowerCase().trim()]
  )
  
  return users[0] || null
}

function isValidEmail(email) {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
  return emailRegex.test(email) && email.length <= 255
}
```

### API Security

**Secure API Design**
```javascript
// src/routes/api/users/[id]/+server.js
import { json, error } from '@sveltejs/kit'
import { rateLimit } from '$lib/server/rateLimit.js'

const getUserRateLimit = rateLimit({ max: 100, windowMs: 15 * 60 * 1000 })

export async function GET({ params, request, locals }) {
  // Rate limiting
  if (!getUserRateLimit(request)) {
    throw error(429, 'Too many requests')
  }
  
  // Authentication
  if (!locals.user) {
    throw error(401, 'Authentication required')
  }
  
  // Authorization - users can only access their own data or admins can access all
  const userId = parseInt(params.id)
  if (locals.user.id !== userId && locals.user.role !== 'admin') {
    throw error(403, 'Access denied')
  }
  
  // Input validation
  if (isNaN(userId) || userId <= 0) {
    throw error(400, 'Invalid user ID')
  }
  
  try {
    const user = await getUserById(userId)
    
    if (!user) {
      throw error(404, 'User not found')
    }
    
    // Sanitize response - remove sensitive data
    const safeUser = {
      id: user.id,
      email: user.email,
      name: user.name,
      createdAt: user.createdAt
      // Don't include: password, resetTokens, etc.
    }
    
    return json(safeUser)
  } catch (err) {
    console.error('Error fetching user:', err)
    throw error(500, 'Internal server error')
  }
}
```

## Deployment Security

### Production Environment Security

**Secure svelte.config.js for Production**
```javascript
// svelte.config.js
import adapter from '@sveltejs/adapter-vercel'

const config = {
  kit: {
    adapter: adapter(),
    csrf: {
      checkOrigin: true,
    },
    csp: {
      mode: 'hash',
      directives: {
        'default-src': ['self'],
        'script-src': ['self'],
        'style-src': ['self', 'unsafe-inline'],
        'img-src': ['self', 'data:', 'https:'],
        'connect-src': ['self', 'https://api.example.com'],
        'frame-ancestors': ['none'],
        'base-uri': ['self'],
        'form-action': ['self']
      },
      reportOnly: process.env.NODE_ENV === 'development'
    },
    // Remove sensitive information in production
    inlineStyleThreshold: process.env.NODE_ENV === 'production' ? 0 : Infinity,
    trailingSlash: 'never',
    prerender: {
      handleHttpError: 'warn'
    }
  }
}

export default config
```

### Vercel Deployment Security

**vercel.json Security Configuration**
```json
{
  "headers": [
    {
      "source": "/(.*)",
      "headers": [
        {
          "key": "X-Frame-Options",
          "value": "DENY"
        },
        {
          "key": "X-Content-Type-Options",
          "value": "nosniff"
        },
        {
          "key": "Referrer-Policy",
          "value": "strict-origin-when-cross-origin"
        },
        {
          "key": "Strict-Transport-Security",
          "value": "max-age=31536000; includeSubDomains; preload"
        }
      ]
    }
  ],
  "env": {
    "NODE_ENV": "production"
  }
}
```

### Cloudflare Pages Security

**_headers file for Cloudflare Pages**
```
/*
  X-Frame-Options: DENY
  X-Content-Type-Options: nosniff
  Referrer-Policy: strict-origin-when-cross-origin
  Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
  Permissions-Policy: camera=(), microphone=(), geolocation=()
  Cross-Origin-Embedder-Policy: require-corp
  Cross-Origin-Opener-Policy: same-origin
  Cross-Origin-Resource-Policy: same-origin

/api/*
  X-Robots-Tag: noindex

/_app/*
  Cache-Control: public, max-age=31536000, immutable
```

## Security Testing and Monitoring

### Automated Security Testing

**Security Test Suite**
```javascript
// tests/security.test.js
import { expect, test } from '@playwright/test'

test.describe('Security Tests', () => {
  test('should have secure headers', async ({ page }) => {
    const response = await page.goto('/')
    
    // Check security headers
    expect(response.headers()['x-frame-options']).toBe('DENY')
    expect(response.headers()['x-content-type-options']).toBe('nosniff')
    expect(response.headers()['strict-transport-security']).toBeTruthy()
  })
  
  test('should prevent XSS in form inputs', async ({ page }) => {
    await page.goto('/contact')
    
    const maliciousScript = '<script>alert("XSS")</script>'
    await page.fill('[name="message"]', maliciousScript)
    await page.click('button[type="submit"]')
    
    // Script should not execute
    const pageContent = await page.content()
    expect(pageContent).not.toContain('<script>alert("XSS")</script>')
  })
  
  test('should enforce CSRF protection', async ({ request }) => {
    // Attempt cross-origin POST without proper headers
    const response = await request.post('/api/sensitive-action', {
      data: { action: 'delete' },
      headers: {
        'Origin': 'https://malicious-site.com'
      }
    })
    
    expect(response.status()).toBe(403)
  })
})
```

### Runtime Security Monitoring

```javascript
// src/lib/server/monitoring.js
export class SecurityMonitor {
  static logSecurityEvent(event, details) {
    const logEntry = {
      timestamp: new Date().toISOString(),
      type: 'security',
      event,
      details,
      severity: this.getSeverity(event)
    }
    
    // Log to console in development
    if (process.env.NODE_ENV === 'development') {
      console.warn('Security Event:', logEntry)
    }
    
    // Send to monitoring service in production
    if (process.env.NODE_ENV === 'production') {
      this.sendToMonitoringService(logEntry)
    }
  }
  
  static getSeverity(event) {
    const severityMap = {
      'csrf_attempt': 'high',
      'xss_attempt': 'high',
      'rate_limit_exceeded': 'medium',
      'invalid_auth': 'medium',
      'suspicious_input': 'low'
    }
    
    return severityMap[event] || 'low'
  }
  
  static async sendToMonitoringService(logEntry) {
    try {
      // Example: Send to Sentry, LogRocket, or custom service
      await fetch('https://your-monitoring-service.com/security-events', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(logEntry)
      })
    } catch (error) {
      console.error('Failed to send security event to monitoring service:', error)
    }
  }
}
```

### CSP Violation Monitoring

```javascript
// src/routes/api/csp-report/+server.js
import { json } from '@sveltejs/kit'
import { SecurityMonitor } from '$lib/server/monitoring.js'

export async function POST({ request }) {
  try {
    const report = await request.json()
    
    SecurityMonitor.logSecurityEvent('csp_violation', {
      documentUri: report['document-uri'],
      violatedDirective: report['violated-directive'],
      blockedUri: report['blocked-uri'],
      sourceFile: report['source-file'],
      lineNumber: report['line-number'],
      userAgent: request.headers.get('user-agent')
    })
    
    return json({ received: true })
  } catch (error) {
    console.error('Error processing CSP report:', error)
    return json({ error: 'Failed to process report' }, { status: 400 })
  }
}
```

## Security Checklist

### Pre-Deployment Security Checklist

- [ ] **Authentication & Authorization**
  - [ ] Implement proper authentication system
  - [ ] Use secure session management
  - [ ] Implement role-based access control
  - [ ] Protect sensitive routes with middleware

- [ ] **Input Validation & Sanitization**
  - [ ] Validate all user inputs server-side
  - [ ] Sanitize data before database operations
  - [ ] Use parameterized queries to prevent SQL injection
  - [ ] Implement rate limiting on API endpoints

- [ ] **XSS Prevention**
  - [ ] Avoid `@html` directive with user content
  - [ ] Sanitize HTML when `@html` is necessary
  - [ ] Implement Content Security Policy
  - [ ] Validate and sanitize URLs in links and images

- [ ] **CSRF Protection**
  - [ ] Enable SvelteKit's built-in CSRF protection
  - [ ] Implement custom CSRF tokens for sensitive operations
  - [ ] Validate origin headers
  - [ ] Use SameSite cookies

- [ ] **Security Headers**
  - [ ] Implement comprehensive security headers
  - [ ] Configure CSP with proper directives
  - [ ] Set up HSTS for HTTPS enforcement
  - [ ] Configure CORS policies appropriately

- [ ] **Environment & Deployment**
  - [ ] Secure environment variables
  - [ ] Remove debug information in production
  - [ ] Configure secure cookies
  - [ ] Set up monitoring and logging

- [ ] **Testing**
  - [ ] Run security-focused tests
  - [ ] Test for XSS vulnerabilities
  - [ ] Validate CSRF protection
  - [ ] Check for information disclosure

### Security Maintenance

- **Regular Updates**: Keep SvelteKit and dependencies updated
- **Security Audits**: Run `npm audit` regularly and fix vulnerabilities
- **Monitoring**: Implement real-time security monitoring
- **Backup & Recovery**: Ensure secure backup and recovery procedures
- **Incident Response**: Have a plan for security incidents

## Conclusion

Security in SvelteKit applications requires a multi-layered approach covering authentication, input validation, XSS prevention, CSRF protection, and proper deployment practices. By implementing these security measures systematically, you can build robust and secure web applications that protect both your users and your business.

Remember that security is an ongoing process, not a one-time implementation. Stay updated with the latest security best practices, regularly audit your application, and always treat user input as potentially malicious until proven otherwise.

The security landscape is constantly evolving, so make sure to:
- Stay informed about new vulnerabilities
- Update dependencies regularly
- Monitor your application for suspicious activity
- Review and update security measures periodically
- Conduct regular security audits and penetration testing

By following this comprehensive guide, you'll have a solid foundation for building secure SvelteKit applications that can withstand common security threats and protect your users' data.