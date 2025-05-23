<script lang="ts">
	import { Button } from '$lib/components/ui/button';
	import * as Card from '$lib/components/ui/card';
	import { Badge } from '$lib/components/ui/badge';
	import { ExternalLink, Code, Package, Palette, Zap, Code2, CheckCircle2 } from 'lucide-svelte';
</script>

<div class="container mx-auto px-4 py-16 max-w-6xl">
	<div class="text-center mb-16">
		<h1
			class="text-5xl font-bold mb-4 bg-gradient-to-r from-primary to-primary/60 bg-clip-text text-transparent"
		>
			SvelteKit + Tailwind + shadcn-svelte
		</h1>
		<p class="text-xl text-muted-foreground max-w-2xl mx-auto">
			A modern web application starter template with the best tools for building fast, beautiful,
			and accessible apps
		</p>
		<div class="flex gap-4 justify-center mt-8">
			<Button href="/shadcn-component-test" size="lg">
				<Palette class="mr-2 h-4 w-4" />
				View Components
			</Button>
			<Button href="https://github.com" variant="outline" size="lg">
				<Code class="mr-2 h-4 w-4" />
				GitHub
			</Button>
		</div>
	</div>

	<div class="grid gap-8 md:grid-cols-2 lg:grid-cols-3 mb-16">
		<Card.Root>
			<Card.Header>
				<div class="flex items-center gap-2">
					<div class="p-2 bg-primary/10 rounded-lg">
						<Zap class="h-6 w-6 text-primary" />
					</div>
					<Card.Title>SvelteKit</Card.Title>
				</div>
			</Card.Header>
			<Card.Content>
				<p class="text-muted-foreground mb-4">
					Full-stack framework for building blazingly fast web applications with built-in routing,
					SSR, and API endpoints.
				</p>
				<div class="flex gap-2">
					<Badge variant="secondary">v2.16.0</Badge>
					<Badge variant="outline">SSR/SSG</Badge>
				</div>
			</Card.Content>
			<Card.Footer>
				<Button variant="link" href="https://kit.svelte.dev" class="p-0">
					Learn more <ExternalLink class="ml-1 h-3 w-3" />
				</Button>
			</Card.Footer>
		</Card.Root>

		<Card.Root>
			<Card.Header>
				<div class="flex items-center gap-2">
					<div class="p-2 bg-primary/10 rounded-lg">
						<Code2 class="h-6 w-6 text-primary" />
					</div>
					<Card.Title>Svelte 5</Card.Title>
				</div>
			</Card.Header>
			<Card.Content>
				<p class="text-muted-foreground mb-4">
					Reactive UI framework with runes, enhanced reactivity, and compile-time optimizations for
					minimal bundle size.
				</p>
				<div class="flex gap-2">
					<Badge variant="secondary">v5.0.0</Badge>
					<Badge variant="outline">Runes</Badge>
				</div>
			</Card.Content>
			<Card.Footer>
				<Button variant="link" href="https://svelte.dev" class="p-0">
					Learn more <ExternalLink class="ml-1 h-3 w-3" />
				</Button>
			</Card.Footer>
		</Card.Root>

		<Card.Root>
			<Card.Header>
				<div class="flex items-center gap-2">
					<div class="p-2 bg-primary/10 rounded-lg">
						<Palette class="h-6 w-6 text-primary" />
					</div>
					<Card.Title>Tailwind CSS v4</Card.Title>
				</div>
			</Card.Header>
			<Card.Content>
				<p class="text-muted-foreground mb-4">
					Next-generation utility-first CSS framework with improved performance and developer
					experience.
				</p>
				<div class="flex gap-2">
					<Badge variant="secondary">v4.0.0</Badge>
					<Badge variant="outline">Lightning CSS</Badge>
				</div>
			</Card.Content>
			<Card.Footer>
				<Button variant="link" href="https://tailwindcss.com" class="p-0">
					Learn more <ExternalLink class="ml-1 h-3 w-3" />
				</Button>
			</Card.Footer>
		</Card.Root>

		<Card.Root>
			<Card.Header>
				<div class="flex items-center gap-2">
					<div class="p-2 bg-primary/10 rounded-lg">
						<Package class="h-6 w-6 text-primary" />
					</div>
					<Card.Title>shadcn-svelte</Card.Title>
				</div>
			</Card.Header>
			<Card.Content>
				<p class="text-muted-foreground mb-4">
					Beautiful, accessible components built with Radix UI and Tailwind CSS. Copy, paste, and
					customize.
				</p>
				<div class="flex gap-2">
					<Badge variant="secondary">v1.0.0-next</Badge>
					<Badge variant="outline">21+ Components</Badge>
				</div>
			</Card.Content>
			<Card.Footer>
				<Button variant="link" href="https://www.shadcn-svelte.com" class="p-0">
					Learn more <ExternalLink class="ml-1 h-3 w-3" />
				</Button>
			</Card.Footer>
		</Card.Root>

		<Card.Root>
			<Card.Header>
				<div class="flex items-center gap-2">
					<div class="p-2 bg-primary/10 rounded-lg">
						<Code2 class="h-6 w-6 text-primary" />
					</div>
					<Card.Title>TypeScript</Card.Title>
				</div>
			</Card.Header>
			<Card.Content>
				<p class="text-muted-foreground mb-4">
					Static type checking for JavaScript, enabling better IDE support and catching errors at
					compile time.
				</p>
				<div class="flex gap-2">
					<Badge variant="secondary">v5.0.0</Badge>
					<Badge variant="outline">Strict Mode</Badge>
				</div>
			</Card.Content>
			<Card.Footer>
				<Button variant="link" href="https://www.typescriptlang.org" class="p-0">
					Learn more <ExternalLink class="ml-1 h-3 w-3" />
				</Button>
			</Card.Footer>
		</Card.Root>

		<Card.Root>
			<Card.Header>
				<div class="flex items-center gap-2">
					<div class="p-2 bg-primary/10 rounded-lg">
						<Zap class="h-6 w-6 text-primary" />
					</div>
					<Card.Title>Vite</Card.Title>
				</div>
			</Card.Header>
			<Card.Content>
				<p class="text-muted-foreground mb-4">
					Lightning-fast build tool with instant HMR, optimized builds, and excellent developer
					experience.
				</p>
				<div class="flex gap-2">
					<Badge variant="secondary">v6.2.6</Badge>
					<Badge variant="outline">HMR</Badge>
				</div>
			</Card.Content>
			<Card.Footer>
				<Button variant="link" href="https://vitejs.dev" class="p-0">
					Learn more <ExternalLink class="ml-1 h-3 w-3" />
				</Button>
			</Card.Footer>
		</Card.Root>
	</div>

	<Card.Root>
		<Card.Header>
			<Card.Title>Features</Card.Title>
			<Card.Description>Everything you need to build modern web applications</Card.Description>
		</Card.Header>
		<Card.Content>
			<div class="grid gap-4 md:grid-cols-2">
				<div class="flex items-start gap-3">
					<CheckCircle2 class="h-5 w-5 text-primary mt-0.5" />
					<div>
						<p class="font-medium">Pre-configured Setup</p>
						<p class="text-sm text-muted-foreground">
							TypeScript, Tailwind CSS, and shadcn-svelte ready to use
						</p>
					</div>
				</div>
				<div class="flex items-start gap-3">
					<CheckCircle2 class="h-5 w-5 text-primary mt-0.5" />
					<div>
						<p class="font-medium">Component Library</p>
						<p class="text-sm text-muted-foreground">
							21+ beautiful, accessible components installed
						</p>
					</div>
				</div>
				<div class="flex items-start gap-3">
					<CheckCircle2 class="h-5 w-5 text-primary mt-0.5" />
					<div>
						<p class="font-medium">Path Aliases</p>
						<p class="text-sm text-muted-foreground">
							Clean imports with @/* pointing to src/lib/*
						</p>
					</div>
				</div>
				<div class="flex items-start gap-3">
					<CheckCircle2 class="h-5 w-5 text-primary mt-0.5" />
					<div>
						<p class="font-medium">Design System</p>
						<p class="text-sm text-muted-foreground">Customizable theme with CSS variables</p>
					</div>
				</div>
			</div>
		</Card.Content>
	</Card.Root>
</div>
