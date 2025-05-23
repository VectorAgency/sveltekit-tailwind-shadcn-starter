<script lang="ts">
	import '../app.css';
	import Navigation from '$lib/components/navigation.svelte';

	let { children } = $props();
</script>

<Navigation />
<main>
	{@render children()}
</main>
