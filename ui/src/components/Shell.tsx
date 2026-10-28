import { Link, Outlet, useNavigate, useRouterState } from '@tanstack/react-router';
import {
	Bolt,
	Bot,
	Boxes,
	ChevronDown,
	FileCode2,
	GitFork,
	Globe,
	Home,
	LogOut,
	Menu,
	Moon,
	Play,
	Route,
	ScrollText,
	Server,
	Shield,
	ShieldCheck,
	Sun,
	UserRound
} from 'lucide-react';
import { useEffect, useRef, useState } from 'react';

import { apiBase } from '@/api/base';
import type { RuntimeCapabilities, RuntimeUser } from '@/api/runtimeApi';
import { StatusBanner, Tooltip, useDismissiblePopover } from '@/components/Primitives';
import { useRuntimeInfo } from '@/hooks';

type NavItemConfig = {
	to: string;
	label: string;
	icon: React.ComponentType<{ size?: number }>;
	placeholder?: boolean;
	groupStart?: boolean;
	exact?: boolean;
};

const projectLinks = [
	{
		label: 'GitHub',
		href: 'https://github.com/hsuhinyu-sketch/AI-Security-Platform',
		icon: GitFork
	},
	{
		label: 'Platform Overview',
		href: '/',
		icon: Globe
	}
] as const;

export function Shell() {
	const router = useRouterState();
	const runtime = useRuntimeInfo();
	const diagnostic = runtime.data?.ui.managementMode === 'diagnostic';
	const diagnosticPathAllowed = ['/', '/security/events', '/llm/logs'].includes(
		router.location.pathname
	);
	const [theme, setTheme] = useState(
		() =>
			localStorage.getItem('theme') ??
			(window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light')
	);
	const [mobileNavOpen, setMobileNavOpen] = useState(false);
	const mobileNavRef = useDismissiblePopover<HTMLDivElement>(mobileNavOpen, () =>
		setMobileNavOpen(false)
	);
	const navGroups = navigationGroups({
		diagnostic,
		capabilities: runtime.data?.ui.capabilities
	});
	const nav = navGroups.flatMap(group => group.items);
	const currentNav =
		nav
			.filter(item => navItemActive(item, router.location.pathname))
			.sort((left, right) => right.to.length - left.to.length)[0] ?? nav[0];
	const CurrentIcon = currentNav.icon;

	useEffect(() => {
		document.documentElement.dataset.theme = theme;
	}, [theme]);

	// biome-ignore lint/correctness/useExhaustiveDependencies: Existing lint violation; remove this suppression when the underlying issue is fixed.
	useEffect(() => {
		setMobileNavOpen(false);
	}, [router.location.pathname]);

	return (
		<div className="app-shell">
			<aside className="sidebar">
				<Link to="/" className="brand" aria-label="AI Security Platform home">
					<span className="platform-wordmark">
						AI Security
						<br />
						Platform
					</span>
				</Link>
				<nav className="nav-list" aria-label="Primary">
					{navGroups.map(group => (
						<NavSection
							key={group.title}
							title={group.title}
							items={group.items}
							currentPath={router.location.pathname}
						/>
					))}
				</nav>
				<div className="sidebar-links">
					{projectLinks.map(link => {
						const Icon = link.icon;
						return (
							<Tooltip content={link.label} key={link.href} side="top">
								<a
									className="sidebar-link"
									href={link.href}
									target="_blank"
									rel="noreferrer"
									aria-label={link.label}
								>
									<Icon size={17} />
								</a>
							</Tooltip>
						);
					})}
				</div>
			</aside>
			<div className="main-area">
				<header className="topbar">
					<div className="topbar-left">
						<div className="mobile-nav" ref={mobileNavRef}>
							<button
								className="mobile-nav-trigger"
								type="button"
								aria-expanded={mobileNavOpen}
								onClick={() => setMobileNavOpen(open => !open)}
							>
								<Menu size={17} />
								<CurrentIcon size={16} />
								<span>{currentNav.label}</span>
							</button>
							{mobileNavOpen ? (
								<nav className="mobile-nav-menu" aria-label="Primary">
									{navGroups.map(group => (
										<MobileNavSection
											key={group.title}
											title={group.title}
											items={group.items}
											currentPath={router.location.pathname}
										/>
									))}
								</nav>
							) : null}
						</div>
						<span className="eyebrow">{eyebrowForPath(router.location.pathname)}</span>
					</div>
					<div className="topbar-controls">
						{runtime.data?.user && <UserMenu user={runtime.data.user} />}
						<Tooltip content="Toggle theme">
							<button
								className="icon-button"
								type="button"
								aria-label="Toggle theme"
								onClick={() => {
									const next = theme === 'dark' ? 'light' : 'dark';
									localStorage.setItem('theme', next);
									setTheme(next);
								}}
							>
								{theme === 'dark' ? <Sun size={18} /> : <Moon size={18} />}
							</button>
						</Tooltip>
					</div>
				</header>
				<main className="content">
					{runtime.data?.ui.configStoreMode === 'readOnly' && (
						<StatusBanner state="info" title="Read-only mode">
							The UI is configured as read-only. Editing is disabled.
						</StatusBanner>
					)}
					{diagnostic && !diagnosticPathAllowed ? (
						<StatusBanner state="info" title="Local diagnostics">
							此部署只开放日志和安全事件查看。请通过左侧菜单访问诊断页面。
						</StatusBanner>
					) : (
						<Outlet />
					)}
				</main>
			</div>
		</div>
	);
}

function UserMenu({ user }: { user: RuntimeUser }) {
	const [open, setOpen] = useState(false);
	const trigger = useRef<HTMLButtonElement>(null);
	const ref = useDismissiblePopover<HTMLDivElement>(open, () => {
		setOpen(false);
		trigger.current?.focus();
	});
	const label = user.name || user.email || user.subject || 'Signed in';
	const initials = user.name
		? user.name
				.split(/\s+/)
				.slice(0, 2)
				.map(part => Array.from(part)[0])
				.join('')
				.toLocaleUpperCase()
		: Array.from(user.email || user.subject || '')
				.slice(0, 1)
				.join('')
				.toLocaleUpperCase();

	return (
		<div className="user-menu" ref={ref}>
			<button
				ref={trigger}
				className="user-menu-trigger"
				type="button"
				aria-label={`Account: ${label}`}
				aria-expanded={open}
				aria-controls="user-menu-panel"
				onClick={() => setOpen(!open)}
			>
				<span className="user-avatar" aria-hidden="true">
					{initials || <UserRound size={16} />}
				</span>
				<span className="user-menu-name">{label}</span>
				<ChevronDown size={14} aria-hidden="true" />
			</button>
			{open && (
				<section id="user-menu-panel" className="user-menu-panel" aria-label="Your account">
					<div className="user-menu-identity">
						<span className="user-menu-caption">Signed in as</span>
						<strong>{label}</strong>
						{user.email && user.email !== label && <span>{user.email}</span>}
					</div>
					{user.canLogout && (
						<form action={`${apiBase}/api/auth/logout`} method="post">
							<button className="user-menu-signout" type="submit">
								<LogOut size={16} aria-hidden="true" />
								Sign out
							</button>
						</form>
					)}
				</section>
			)}
		</div>
	);
}

function navigationGroups(options: {
	diagnostic: boolean;
	capabilities?: RuntimeCapabilities;
}): ReadonlyArray<{ title: string; items: readonly NavItemConfig[] }> {
	if (options.diagnostic) {
		return [
			{
				title: 'Local diagnostics',
				items: [
					{ to: '/', label: 'Home', icon: Home },
					{ to: '/security/events', label: 'Security Events', icon: Shield },
					{ to: '/llm/logs', label: 'Request Logs', icon: ScrollText }
				]
			}
		];
	}

	const hasLlm = options.capabilities?.llm === true;
	const hasMcp = options.capabilities?.mcp === true;
	const hasInference = options.capabilities?.inferenceRouting === true;

	return [
		{
			title: 'Gateway',
			items: [
				{ to: '/', label: 'Home', icon: Home },
				{ to: '/gateway-workbench', label: 'Gateway Workbench', icon: Boxes }
			]
		},
		...(hasLlm
			? [
					{
						title: 'LLM',
						items: [
							{ to: '/llm/models', label: 'Models', icon: Bot },
							{ to: '/llm/providers', label: 'Providers', icon: Boxes },
							{ to: '/llm/policies', label: 'Policies', icon: Bolt, groupStart: true },
							{ to: '/llm/guardrails', label: 'Guardrails', icon: Shield },
							{ to: '/llm/logs', label: 'Logs', icon: ScrollText },
							{ to: '/llm/playground', label: 'Chat Playground', icon: Play }
						]
					}
				]
			: []),
		...(hasMcp
			? [
					{
						title: 'MCP',
						items: [
							{ to: '/mcp/servers', label: 'Servers', icon: Server },
							{ to: '/mcp/policies', label: 'Policies', icon: ShieldCheck },
							{ to: '/mcp/playground', label: 'Tool Playground', icon: Play }
						]
					}
				]
			: []),
		...(hasInference
			? [
					{
						title: 'Inference Routing',
						items: [{ to: '/raw-config', label: 'Routing Config', icon: Route, exact: true }]
					}
				]
			: []),
		{
			title: 'Security',
			items: [{ to: '/security/events', label: 'Security Events', icon: Shield }]
		},
		{
			title: 'Platform',
			items: [{ to: '/raw-config', label: 'Raw Configuration', icon: FileCode2, exact: true }]
		}
	];
}

function NavSection(props: {
	title: string;
	items: readonly NavItemConfig[];
	currentPath: string;
}) {
	return (
		<>
			<div className="nav-section">{props.title}</div>
			{props.items.map(item => (
				<NavItem key={item.to} {...item} currentPath={props.currentPath} />
			))}
		</>
	);
}

function MobileNavSection(props: {
	title: string;
	items: readonly NavItemConfig[];
	currentPath: string;
}) {
	return (
		<>
			<div className="mobile-nav-section">{props.title}</div>
			{props.items.map(item => (
				<MobileNavItem key={item.to} {...item} currentPath={props.currentPath} />
			))}
		</>
	);
}

function MobileNavItem(props: {
	to: string;
	label: string;
	icon: React.ComponentType<{ size?: number }>;
	currentPath: string;
	placeholder?: boolean;
	groupStart?: boolean;
	exact?: boolean;
}) {
	const Icon = props.icon;
	const navigate = useNavigate();
	const active = props.placeholder ? false : navItemActive(props, props.currentPath);
	if (props.placeholder) {
		return (
			<button
				type="button"
				className={props.groupStart ? 'mobile-nav-item nav-group-start' : 'mobile-nav-item'}
				onClick={() => void navigate({ to: props.to })}
			>
				<Icon size={16} />
				<span>{props.label}</span>
			</button>
		);
	}
	return (
		<Link
			to={props.to}
			className={`${active ? 'mobile-nav-item active' : 'mobile-nav-item'}${props.groupStart ? ' nav-group-start' : ''}`}
		>
			<Icon size={16} />
			<span>{props.label}</span>
		</Link>
	);
}

function eyebrowForPath(path: string) {
	if (path === '/') return 'Platform overview';
	if (path.startsWith('/security')) return 'Runtime security';
	if (path.startsWith('/mcp')) return 'MCP configuration';
	if (path.startsWith('/traffic')) return 'Traffic configuration';
	if (path.startsWith('/cel') || path.startsWith('/raw-config') || path.startsWith('/settings'))
		return 'Policy tools';
	return 'LLM configuration';
}

function NavItem(props: {
	to: string;
	label: string;
	icon: React.ComponentType<{ size?: number }>;
	currentPath: string;
	placeholder?: boolean;
	groupStart?: boolean;
	exact?: boolean;
}) {
	const Icon = props.icon;
	const navigate = useNavigate();
	const active = props.placeholder ? false : navItemActive(props, props.currentPath);
	if (props.placeholder) {
		return (
			<button
				type="button"
				className={props.groupStart ? 'nav-item nav-group-start' : 'nav-item'}
				onClick={() => void navigate({ to: props.to })}
			>
				<Icon size={17} />
				<span>{props.label}</span>
			</button>
		);
	}
	return (
		<Link
			to={props.to}
			className={`${active ? 'nav-item active' : 'nav-item'}${props.groupStart ? ' nav-group-start' : ''}`}
		>
			<Icon size={17} />
			<span>{props.label}</span>
		</Link>
	);
}

function navItemActive(item: { to: string; exact?: boolean }, path: string) {
	if (item.to === '/') return path === '/';
	if (item.exact) return path === item.to;
	return path === item.to || path.startsWith(`${item.to}/`);
}
