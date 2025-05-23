<script lang="ts">
	import { Button, buttonVariants } from '$lib/components/ui/button';
	import * as Card from '$lib/components/ui/card';
	import * as Dialog from '$lib/components/ui/dialog';
	import { Input } from '$lib/components/ui/input';
	import { Label } from '$lib/components/ui/label';
	import * as Select from '$lib/components/ui/select';
	import { Textarea } from '$lib/components/ui/textarea';
	import { Checkbox } from '$lib/components/ui/checkbox';
	import * as RadioGroup from '$lib/components/ui/radio-group';
	import { Switch } from '$lib/components/ui/switch';
	import * as Tabs from '$lib/components/ui/tabs';
	import * as Alert from '$lib/components/ui/alert';
	import { Badge } from '$lib/components/ui/badge';
	import * as DropdownMenu from '$lib/components/ui/dropdown-menu';
	import { Separator } from '$lib/components/ui/separator';
	import * as Accordion from '$lib/components/ui/accordion';
	import * as Avatar from '$lib/components/ui/avatar';
	import * as Sheet from '$lib/components/ui/sheet';
	import * as Popover from '$lib/components/ui/popover';
	import * as Tooltip from '$lib/components/ui/tooltip';
	import { Progress } from '$lib/components/ui/progress';
	import * as Collapsible from '$lib/components/ui/collapsible';
	import { ChevronsUpDown, AlertCircle, Terminal, User, Menu } from 'lucide-svelte';

	let checked = $state(false);
	let switchChecked = $state(false);
	let inputValue = $state('');
	let textareaValue = $state('');
	let progressValue = $state(33);
	let selectedValue = $state('');
</script>

<div class="container mx-auto p-8 space-y-8">
	<h1 class="text-4xl font-bold mb-8">Shadcn Component Test</h1>

	<!-- Buttons -->
	<section class="space-y-4">
		<h2 class="text-2xl font-semibold">Buttons</h2>
		<div class="flex gap-4 flex-wrap">
			<Button>Default</Button>
			<Button variant="secondary">Secondary</Button>
			<Button variant="destructive">Destructive</Button>
			<Button variant="outline">Outline</Button>
			<Button variant="ghost">Ghost</Button>
			<Button variant="link">Link</Button>
		</div>
	</section>

	<Separator />

	<!-- Cards -->
	<section class="space-y-4">
		<h2 class="text-2xl font-semibold">Cards</h2>
		<Card.Root class="w-[350px]">
			<Card.Header>
				<Card.Title>Card Title</Card.Title>
				<Card.Description>Card description goes here.</Card.Description>
			</Card.Header>
			<Card.Content>
				<p>Card content with some example text.</p>
			</Card.Content>
			<Card.Footer>
				<Button variant="outline">Cancel</Button>
				<Button>Save</Button>
			</Card.Footer>
		</Card.Root>
	</section>

	<Separator />

	<!-- Forms -->
	<section class="space-y-4">
		<h2 class="text-2xl font-semibold">Form Elements</h2>

		<div class="space-y-2">
			<Label for="input">Input</Label>
			<Input id="input" placeholder="Type something..." bind:value={inputValue} />
			<p class="text-sm text-muted-foreground">You typed: {inputValue}</p>
		</div>

		<div class="space-y-2">
			<Label for="textarea">Textarea</Label>
			<Textarea id="textarea" placeholder="Type your message..." bind:value={textareaValue} />
		</div>

		<div class="flex items-center space-x-2">
			<Checkbox id="checkbox" bind:checked />
			<Label for="checkbox">Accept terms and conditions</Label>
		</div>

		<div class="space-y-2">
			<Label>Radio Group</Label>
			<RadioGroup.Root value="option1">
				<div class="flex items-center space-x-2">
					<RadioGroup.Item value="option1" id="r1" />
					<Label for="r1">Option 1</Label>
				</div>
				<div class="flex items-center space-x-2">
					<RadioGroup.Item value="option2" id="r2" />
					<Label for="r2">Option 2</Label>
				</div>
			</RadioGroup.Root>
		</div>

		<div class="flex items-center space-x-2">
			<Switch id="switch" bind:checked={switchChecked} />
			<Label for="switch">Enable notifications</Label>
		</div>

		<div class="space-y-2">
			<Label>Select</Label>
			<Select.Root type="single" bind:value={selectedValue}>
				<Select.Trigger class="w-[200px]">
					<span data-slot="select-value">{selectedValue || 'Select an option'}</span>
				</Select.Trigger>
				<Select.Content>
					<Select.Item value="option1">Option 1</Select.Item>
					<Select.Item value="option2">Option 2</Select.Item>
					<Select.Item value="option3">Option 3</Select.Item>
				</Select.Content>
			</Select.Root>
		</div>
	</section>

	<Separator />

	<!-- Badges -->
	<section class="space-y-4">
		<h2 class="text-2xl font-semibold">Badges</h2>
		<div class="flex gap-2 flex-wrap">
			<Badge>Default</Badge>
			<Badge variant="secondary">Secondary</Badge>
			<Badge variant="destructive">Destructive</Badge>
			<Badge variant="outline">Outline</Badge>
		</div>
	</section>

	<Separator />

	<!-- Alerts -->
	<section class="space-y-4">
		<h2 class="text-2xl font-semibold">Alerts</h2>
		<Alert.Root>
			<Terminal class="h-4 w-4" />
			<Alert.Title>Heads up!</Alert.Title>
			<Alert.Description>You can add components to your app using the CLI.</Alert.Description>
		</Alert.Root>
		<Alert.Root variant="destructive">
			<AlertCircle class="h-4 w-4" />
			<Alert.Title>Error</Alert.Title>
			<Alert.Description>Your session has expired. Please log in again.</Alert.Description>
		</Alert.Root>
	</section>

	<Separator />

	<!-- Tabs -->
	<section class="space-y-4">
		<h2 class="text-2xl font-semibold">Tabs</h2>
		<Tabs.Root value="tab1" class="w-[400px]">
			<Tabs.List>
				<Tabs.Trigger value="tab1">Account</Tabs.Trigger>
				<Tabs.Trigger value="tab2">Password</Tabs.Trigger>
			</Tabs.List>
			<Tabs.Content value="tab1" class="space-y-4">
				<h3 class="text-lg font-medium">Account</h3>
				<p>Make changes to your account here.</p>
			</Tabs.Content>
			<Tabs.Content value="tab2" class="space-y-4">
				<h3 class="text-lg font-medium">Password</h3>
				<p>Change your password here.</p>
			</Tabs.Content>
		</Tabs.Root>
	</section>

	<Separator />

	<!-- Accordion -->
	<section class="space-y-4">
		<h2 class="text-2xl font-semibold">Accordion</h2>
		<Accordion.Root type="single" class="w-[400px]">
			<Accordion.Item value="item-1">
				<Accordion.Trigger>Is it accessible?</Accordion.Trigger>
				<Accordion.Content>Yes. It adheres to the WAI-ARIA design pattern.</Accordion.Content>
			</Accordion.Item>
			<Accordion.Item value="item-2">
				<Accordion.Trigger>Is it styled?</Accordion.Trigger>
				<Accordion.Content>
					Yes. It comes with default styles that match the theme.
				</Accordion.Content>
			</Accordion.Item>
		</Accordion.Root>
	</section>

	<Separator />

	<!-- Avatar -->
	<section class="space-y-4">
		<h2 class="text-2xl font-semibold">Avatar</h2>
		<div class="flex gap-4">
			<Avatar.Root>
				<Avatar.Image src="https://github.com/shadcn.png" alt="@shadcn" />
				<Avatar.Fallback>CN</Avatar.Fallback>
			</Avatar.Root>
			<Avatar.Root>
				<Avatar.Fallback>JD</Avatar.Fallback>
			</Avatar.Root>
		</div>
	</section>

	<Separator />

	<!-- Progress -->
	<section class="space-y-4">
		<h2 class="text-2xl font-semibold">Progress</h2>
		<Progress value={progressValue} class="w-[300px]" />
		<Button onclick={() => (progressValue = Math.min(100, progressValue + 10))}>
			Increase Progress
		</Button>
	</section>

	<Separator />

	<!-- Collapsible -->
	<section class="space-y-4">
		<h2 class="text-2xl font-semibold">Collapsible</h2>
		<Collapsible.Root class="w-[350px] space-y-2">
			<div class="flex items-center justify-between space-x-4 px-4">
				<h4 class="text-sm font-semibold">@peduarte starred 3 repositories</h4>
				<Collapsible.Trigger
					class={buttonVariants({ variant: 'ghost', size: 'sm', class: 'w-9 p-0' })}
				>
					<ChevronsUpDown class="h-4 w-4" />
					<span class="sr-only">Toggle</span>
				</Collapsible.Trigger>
			</div>
			<div class="rounded-md border px-4 py-2 font-mono text-sm">@radix-ui/primitives</div>
			<Collapsible.Content class="space-y-2">
				<div class="rounded-md border px-4 py-2 font-mono text-sm">@radix-ui/colors</div>
				<div class="rounded-md border px-4 py-2 font-mono text-sm">@stitches/react</div>
			</Collapsible.Content>
		</Collapsible.Root>
	</section>

	<Separator />

	<!-- Dialog -->
	<section class="space-y-4">
		<h2 class="text-2xl font-semibold">Dialog</h2>
		<Dialog.Root>
			<Dialog.Trigger class={buttonVariants({ variant: 'outline' })}>Open Dialog</Dialog.Trigger>
			<Dialog.Content>
				<Dialog.Header>
					<Dialog.Title>Are you sure?</Dialog.Title>
					<Dialog.Description>
						This action cannot be undone. This will permanently delete your account.
					</Dialog.Description>
				</Dialog.Header>
				<Dialog.Footer>
					<Button variant="outline">Cancel</Button>
					<Button>Continue</Button>
				</Dialog.Footer>
			</Dialog.Content>
		</Dialog.Root>
	</section>

	<Separator />

	<!-- Sheet -->
	<section class="space-y-4">
		<h2 class="text-2xl font-semibold">Sheet</h2>
		<Sheet.Root>
			<Sheet.Trigger class={buttonVariants({ variant: 'outline' })}>Open Sheet</Sheet.Trigger>
			<Sheet.Content>
				<Sheet.Header>
					<Sheet.Title>Edit profile</Sheet.Title>
					<Sheet.Description>
						Make changes to your profile here. Click save when you're done.
					</Sheet.Description>
				</Sheet.Header>
				<div class="space-y-4 py-4">
					<div class="space-y-2">
						<Label for="name">Name</Label>
						<Input id="name" value="Pedro Duarte" />
					</div>
					<div class="space-y-2">
						<Label for="username">Username</Label>
						<Input id="username" value="@peduarte" />
					</div>
				</div>
				<Sheet.Footer>
					<Sheet.Close class={buttonVariants({ variant: 'outline' })}>Save changes</Sheet.Close>
				</Sheet.Footer>
			</Sheet.Content>
		</Sheet.Root>
	</section>

	<Separator />

	<!-- Dropdown Menu -->
	<section class="space-y-4">
		<h2 class="text-2xl font-semibold">Dropdown Menu</h2>
		<DropdownMenu.Root>
			<DropdownMenu.Trigger class={buttonVariants({ variant: 'outline' })}>
				<Menu class="h-4 w-4 mr-2" />
				Open Menu
			</DropdownMenu.Trigger>
			<DropdownMenu.Content>
				<DropdownMenu.Label>My Account</DropdownMenu.Label>
				<DropdownMenu.Separator />
				<DropdownMenu.Item>Profile</DropdownMenu.Item>
				<DropdownMenu.Item>Billing</DropdownMenu.Item>
				<DropdownMenu.Item>Team</DropdownMenu.Item>
				<DropdownMenu.Separator />
				<DropdownMenu.Item>Logout</DropdownMenu.Item>
			</DropdownMenu.Content>
		</DropdownMenu.Root>
	</section>

	<Separator />

	<!-- Popover -->
	<section class="space-y-4">
		<h2 class="text-2xl font-semibold">Popover</h2>
		<Popover.Root>
			<Popover.Trigger class={buttonVariants({ variant: 'outline' })}>Open Popover</Popover.Trigger>
			<Popover.Content class="w-80">
				<div class="grid gap-4">
					<div class="space-y-2">
						<h4 class="font-medium leading-none">Dimensions</h4>
						<p class="text-sm text-muted-foreground">Set the dimensions for the layer.</p>
					</div>
					<div class="grid gap-2">
						<div class="grid grid-cols-3 items-center gap-4">
							<Label for="width">Width</Label>
							<Input id="width" value="100%" class="col-span-2 h-8" />
						</div>
						<div class="grid grid-cols-3 items-center gap-4">
							<Label for="height">Height</Label>
							<Input id="height" value="25px" class="col-span-2 h-8" />
						</div>
					</div>
				</div>
			</Popover.Content>
		</Popover.Root>
	</section>

	<Separator />

	<!-- Tooltip -->
	<section class="space-y-4">
		<h2 class="text-2xl font-semibold">Tooltip</h2>
		<Tooltip.Provider>
			<Tooltip.Root>
				<Tooltip.Trigger class={buttonVariants({ variant: 'outline' })}>
					<User class="h-4 w-4 mr-2" />
					Hover me
				</Tooltip.Trigger>
				<Tooltip.Content>
					<p>This is a tooltip</p>
				</Tooltip.Content>
			</Tooltip.Root>
		</Tooltip.Provider>
	</section>
</div>
