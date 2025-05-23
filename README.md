# SvelteKit + Tailwind CSS + shadcn-svelte Starter

A modern web application starter template featuring SvelteKit, Tailwind CSS v4, and shadcn-svelte components.

## Tech Stack

- **[SvelteKit](https://kit.svelte.dev/)** - Full-stack framework for building web applications
- **[Svelte 5](https://svelte.dev/)** - Reactive UI framework with runes and enhanced reactivity
- **[Tailwind CSS v4](https://tailwindcss.com/)** - Utility-first CSS framework
- **[shadcn-svelte](https://www.shadcn-svelte.com/)** - High-quality, accessible component library
- **[TypeScript](https://www.typescriptlang.org/)** - Type-safe development
- **[Vite](https://vitejs.dev/)** - Fast build tool and dev server

## Features

- ✅ Pre-installed shadcn-svelte components
- ✅ Tailwind CSS v4 with custom design system
- ✅ TypeScript configuration
- ✅ ESLint + Prettier pre-configured
- ✅ Automatic sitemap generation
- ✅ Component showcase at `/shadcn-component-test`
- ✅ Path aliases configured (`@/*` → `src/lib/*`)
- ✅ lucide-svelte icons included
- ✅ Ready for production deployment

## Installation

1. Clone or download this template
2. Install dependencies:

```bash
npm install
# or
pnpm install
# or
yarn install
```

## Project Structure

```
src/
├── lib/
│   ├── components/ui/    # shadcn-svelte components
│   └── utils.ts         # Utility functions (cn, etc.)
├── routes/
│   ├── +page.svelte     # Home page
│   └── shadcn-component-test/  # Component showcase
└── app.css              # Global styles & Tailwind config
```

## Available Routes

- `/` - Home page
- `/shadcn-component-test` - Component showcase and examples
- `/sitemap.xml` - Auto-generated sitemap

## Available Scripts

```bash
npm run dev          # Start development server
npm run build        # Build for production
npm run preview      # Preview production build
npm run check        # Run TypeScript type checking
npm run check:watch  # Run TypeScript type checking in watch mode
npm run lint         # Run ESLint
npm run format       # Format code with Prettier
npm run format:check # Check code formatting
```

## Developing

Start a development server:

```bash
npm run dev

# or start the server and open the app in a new browser tab
npm run dev -- --open
```

## Building

To create a production version of your app:

```bash
npm run build
```

You can preview the production build with `npm run preview`.

> To deploy your app, you may need to install an [adapter](https://svelte.dev/docs/kit/adapters) for your target environment.
