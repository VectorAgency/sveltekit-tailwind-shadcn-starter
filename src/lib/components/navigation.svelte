<script lang="ts">
	import { page } from '$app/state';
	import { Button } from '$lib/components/ui/button';
	import { Home, Palette, Github } from 'lucide-svelte';
</script>

<nav class="border-b">
	<div class="container mx-auto px-4 h-16 flex items-center justify-between">
		<div class="flex items-center gap-6">
			<a href="/" class="font-semibold text-xl"> SvelteKit Starter </a>
			<div class="flex items-center gap-1">
				<Button href="/" variant={page.url.pathname === '/' ? 'secondary' : 'ghost'} size="sm">
					<Home class="h-4 w-4 mr-2" />
					Home
				</Button>
				<Button
					href="/shadcn-component-test"
					variant={page.url.pathname === '/shadcn-component-test' ? 'secondary' : 'ghost'}
					size="sm"
				>
					<Palette class="h-4 w-4 mr-2" />
					Components
				</Button>
			</div>
		</div>
		<Button
			href="https://github.com"
			variant="ghost"
			size="sm"
			target="_blank"
			rel="noopener noreferrer"
		>
			<Github class="h-4 w-4 mr-2" />
			GitHub
		</Button>
	</div>
</nav>
