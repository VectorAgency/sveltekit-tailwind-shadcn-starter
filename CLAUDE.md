# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

### Development

- `npm run dev` - Start development server with hot module replacement
- `npm run build` - Build for production
- `npm run preview` - Preview production build locally
- `npm run check` - Run TypeScript type checking
- `npm run check:watch` - Run TypeScript type checking in watch mode
- `npm run lint` - Run ESLint to check code quality
- `npm run format` - Format code with Prettier
- `npm run format:check` - Check if code is properly formatted

## Architecture

This is a SvelteKit application using Svelte 5 syntax with TailwindCSS v4 and shadcn-svelte components.

### Key Patterns

- **Path Alias**: Use `@/*` to import from `src/lib/*` (e.g., `import { cn } from '@/utils'`)
- **Component Structure**: UI components live in `src/lib/components/ui/` with each component in its own directory containing the `.svelte` file and an `index.ts` barrel export
- **Styling**: TailwindCSS with design tokens defined as CSS custom properties in `src/app.css`
- **Component Props**: Use Svelte 5's `$props()` syntax with TypeScript interfaces and `VariantProps` from `tailwind-variants` for variant typing
- **Class Merging**: Use the `cn()` utility from `src/lib/utils.ts` to merge Tailwind classes with proper precedence

### Icons

- **lucide-svelte** is included for iconography
- Import icons directly: `import { Home, User } from 'lucide-svelte'`
- Icons work seamlessly with Tailwind classes for sizing and styling

### Navigation Patterns

- Use SvelteKit's `$page` store for active route detection
- Implement navigation components in `src/lib/components/`
- Leverage `goto()` from `$app.navigation` for programmatic navigation

### Available Routes

- `/` - Home page
- `/shadcn-component-test` - Component showcase and examples
- `/sitemap.xml` - Auto-generated sitemap

### Component Development

When creating new shadcn-svelte components:

1. Place in `src/lib/components/ui/[component-name]/`
2. Export from `index.ts` for cleaner imports
3. Use `$props()` for prop definitions
4. Include `class: className = undefined` in props for style overrides
5. Use `cn()` to merge default classes with className prop

### Important Svelte 5 + shadcn-svelte Patterns

#### Event Handlers

- Use `onclick` instead of `on:click` (Svelte 5 syntax)
- All event handlers are now properties: `onclick`, `onsubmit`, etc.

#### Component Props

- Components requiring multiple items need `type` prop:
  - `<Select.Root type="single">` or `type="multiple"`
  - `<Accordion.Root type="single">` or `type="multiple"`

#### Select Component

- No `Select.Value` component exists
- Use data-slot pattern for custom display:
  ```svelte
  <Select.Trigger>
  	<span data-slot="select-value">{selectedValue || 'Select an option'}</span>
  </Select.Trigger>
  ```

#### Trigger Components

- The `asChild` and `builders` pattern is deprecated
- Use `buttonVariants()` for styling trigger elements:

  ```svelte
  import {buttonVariants} from '$lib/components/ui/button';

  <Dialog.Trigger class={buttonVariants({ variant: 'outline' })}>Open Dialog</Dialog.Trigger>
  ```

#### State Management

- Use `$app/state` instead of `$app/stores` for page state
- Access page properties directly without `$` prefix:
  ```svelte
  import {page} from '$app/state'; // Use: page.url.pathname (not $page.url.pathname)
  ```

#### Tooltip Component

- Always wrap in `<Tooltip.Provider>` for proper functionality

### Common Gotchas

- Some IDE warnings about deprecated imports (like `Github` from lucide-svelte) may be false positives
- Tailwind v4 uses inline configuration in `app.css`, no separate `tailwind.config.ts` needed
- Always run `npm run check` to verify TypeScript types after component changes

## Code Quality

### ESLint Configuration

- Uses flat config format with TypeScript and Svelte plugins
- Prettier integration prevents style conflicts
- Configured to work with Svelte 5 syntax and TypeScript

### Prettier Configuration

- Uses tabs for indentation
- Single quotes for strings
- No trailing commas
- 100 character line width
- Svelte plugin for proper formatting

### Sitemap Generation

- Automatic sitemap generation at `/sitemap.xml`
- Update the domain in `src/routes/sitemap.xml/+server.ts`
- Add new routes to the `pages` array as needed

## Documentation

Additional project documentation is available in the `docs/` folder:

- @docs/sveltekit-security-guide.md - Security best practices and guidelines for SvelteKit applications
- @docs/sveltekit_tailwind_shadcn_best_practices_and_installation_instructions.md - Best practices and setup instructions for the SvelteKit + TailwindCSS + shadcn-svelte stack
