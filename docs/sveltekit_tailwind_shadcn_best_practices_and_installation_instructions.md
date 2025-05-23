## SvelteKit Development Best Practices

### Project structure fundamentals

A well-organized SvelteKit project follows a clear directory structure that promotes maintainability and scalability. The `src/lib` directory serves as your application's shared code repository, accessible via the `$lib` alias from anywhere in your app. Within this directory, organize components by feature or type, separate server-only code in `src/lib/server`, and maintain dedicated directories for stores, utilities, and types.

The routing system uses file-based conventions where `+page.svelte` files define pages, `+layout.svelte` files create shared layouts, and `+server.js` files establish API endpoints. Route groups, denoted by parentheses like `(auth)`, allow logical organization without affecting URL structure. Dynamic routes use square brackets `[param]` for parameters, with support for optional `[[param]]` and rest `[...param]` parameters.

### Performance optimization strategies

**Server-side rendering optimization** forms the foundation of fast SvelteKit applications. Instead of awaiting all data in load functions, return promises directly to enable streaming:

```javascript
// Streaming approach - data loads progressively
export async function load() {
	return {
		posts: fetchPosts(), // Promise, not awaited
		comments: fetchComments()
	};
}
```

**Code splitting and lazy loading** happen automatically at the route level, but you can optimize further with dynamic imports for heavy components:

```javascript
{#if showHeavyFeature}
  {#await import('./HeavyComponent.svelte') then { default: Component }}
    <Component />
  {/await}
{/if}
```

**Image optimization** using `@sveltejs/enhanced-img` provides automatic format conversion, responsive sizing, and layout shift prevention. Configure proper caching headers for static assets and API responses to reduce server load and improve performance.

### State management approaches

SvelteKit offers multiple state management patterns depending on your needs. **Svelte stores** provide reactive state management for client-side applications:

```javascript
// Custom store with methods
function createCounter() {
	const { subscribe, set, update } = writable(0);
	return {
		subscribe,
		increment: () => update((n) => n + 1),
		decrement: () => update((n) => n - 1),
		reset: () => set(0)
	};
}
```

**Context API** enables component tree state sharing without prop drilling. Set context in parent components and retrieve it in children. Critically, avoid using stores on the server side as they're shared across requests. Instead, pass server state through load functions and use the Context API for component access.

**Form handling** leverages SvelteKit's progressive enhancement with form actions:

```javascript
// +page.server.js
import { fail } from '@sveltejs/kit';

export const actions = {
	default: async ({ request }) => {
		const data = await request.formData();
		const email = data.get('email');

		if (!email) {
			return fail(400, { email, missing: true });
		}

		return { success: true };
	}
};
```

### Testing and quality assurance

**Unit testing with Vitest** provides fast, reliable testing for components and utilities. Mock external dependencies and focus on testing business logic separately from UI components. **Integration testing** validates component interactions using Testing Library, while **end-to-end testing with Playwright** ensures critical user flows work correctly across the entire application.

Establish a comprehensive testing strategy that includes unit tests for utilities and business logic, integration tests for component behavior, and E2E tests for critical user journeys. Use page object patterns in E2E tests for maintainability.

### Security implementation

SvelteKit includes **built-in CSRF protection** through origin checking, protecting against cross-site form submissions. For authentication, **SvelteKitAuth (Auth.js)** provides a robust solution with OAuth support and 68+ built-in providers:

```javascript
// hooks.server.js
import { SvelteKitAuth } from '@auth/sveltekit';
import Google from '@auth/sveltekit/providers/google';

export const handle = SvelteKitAuth({
	providers: [Google({ clientId: GOOGLE_ID, clientSecret: GOOGLE_SECRET })]
});
```

Implement **Content Security Policy (CSP)** headers, validate all user inputs, enforce HTTPS in production, and use secure HTTP-only cookies for session management. Rate limiting should be implemented at the application or reverse proxy level.

### Development workflow optimization

**TypeScript integration** improves code quality and developer experience. Leverage SvelteKit's auto-generated types from `./$types` imports and define interfaces for API responses and form data. Configure ESLint and Prettier with Svelte-specific plugins for consistent code formatting.

Implement **git hooks with Husky** to run linting and type checking before commits. Use conventional commit messages for better changelog generation and team communication. Set up continuous integration pipelines that run tests, type checking, and build verification on every pull request.

### Deployment and monitoring

Choose platform-specific adapters based on your needs. **Vercel** offers zero-configuration deployment with edge functions and ISR support, while **Netlify** provides similar features with excellent build caching. For self-hosted solutions, use the Node adapter with proper process management.

Configure environment variables appropriately, using `$env/static/private` for build-time constants and `$env/dynamic/private` for runtime values. Implement proper error handling with custom error pages and global error handlers that log to external services in production.

Monitor key performance metrics including First Contentful Paint, Largest Contentful Paint, and Time to Interactive. Use tools like Vercel Analytics or custom monitoring solutions to track real-user metrics and identify performance bottlenecks.

### Progressive enhancement principles

Build applications that **work without JavaScript** by default, then enhance with client-side features. Forms should function with standard HTML submission, enhanced with SvelteKit's form actions for better UX. Navigation automatically uses client-side routing when JavaScript is available but falls back gracefully.

This approach ensures accessibility, improves SEO, and provides a baseline experience for all users regardless of their device capabilities or network conditions.
