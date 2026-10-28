import { ShieldCheck } from 'lucide-react';
import { useEffect } from 'react';

import { apiBase } from '@/api/base';

export function LoginPage() {
	const returnTo = new URLSearchParams(window.location.search).get('returnTo') || '/ui';
	const query = new URLSearchParams({ returnTo });

	useEffect(() => {
		document.title = 'Sign in · AI Security Platform';
		document.documentElement.dataset.theme =
			localStorage.getItem('theme') ??
			(window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
	}, []);

	return (
		<main className="login-page">
			<section className="login-card" aria-labelledby="login-heading">
				<div className="login-brand">
					<ShieldCheck size={30} aria-hidden="true" />
					<span className="platform-wordmark">
						AI Security
						<br />
						Platform
					</span>
				</div>
				<h1 id="login-heading">Sign in</h1>
				<p>Sign in with your organization’s identity provider to continue.</p>
				<a className="button primary" href={`${apiBase}/api/auth/login?${query}`}>
					Sign in with SSO
				</a>
			</section>
		</main>
	);
}
