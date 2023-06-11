const request = require('request');
const axios = require('axios');
const { PreloadedUserSettings } = require('discord-protos');
const settingDefault = require('./setting-proto.js');
const { version } = require('./package.json');
const nitro = require('./assets/nitro.js');
const msg = require('./assets/msg.js');
const UserData = require('./assets/user.js');
const Profile = require('./assets/profile.js');
const userAgent = `DiscordBot (https://github.com/aiko-chan-ai/DiscordBotClient, v${version})`;
const crypto = require('crypto');
const Store = require('electron-store');
const moment = require('moment');
const messages = require('./assets/messages');
const api = require('./assets/api');
const text = 'elysia-chan';
const dateFormat = 'YYYY-MM-DDTHH:mm:ss.SSSSSSZ';
const apiBase = 'https://discord.com/api/v9';

const cacheSettings = new Store(); // <id, settings>
const emailSettings = new Map(); // <id, settings>

const defaultDataEmailSetting = {
	categories: {
		social: true,
		communication: true,
		recommendations_and_events: false,
		tips: false,
		updates_and_announcements: false,
	},
	initialized: true,
};

function getDataFromRequest(req, res, callback) {
	let data = '';
	req.on('data', function (chunk) {
		data += chunk;
	});
	req.on('end', function () {
		req.rawBody = data;
		if (data && data.indexOf('{') > -1) {
			req.body = JSON.parse(data);
		}
		callback(req, res);
	});
}

module.exports = function (app, logger, html, patchList, scriptTarget) {
	/**
	 * @param {string} url
	 * @param req
	 * @param res
	 * @returns {*|void}
	 */
	const handlerRequest = (url, req, res) => {
		const headers = {
			Authorization: req.headers['authorization'],
			'Content-Type': 'application/json',
			'User-Agent': userAgent
		};
		const method = req.method.toUpperCase();

		// Author:
		if (url.endsWith(api.users('1056491867375673424'))) return res.send(UserData);
		if (url.includes(api.profile('1056491867375673424'))) return res.send(Profile);
		if (url.includes(api.channelMessages('1000000000000000000'))) return res.send(msg);
		// nitro
		if (url.includes('/store/published-listings/skus/')) {
			if (url.includes('/978380684370378762/subscription-plans')) {
				return res.send(nitro['978380684370378762']);
			} else if (url.includes('/521842865731534868/subscription-plans')) {
				return res.send(nitro['521842865731534868']);
			} else if (url.includes('/521846918637420545/subscription-plans')) {
				return res.send(nitro['521846918637420545']);
			} else if (url.includes('/521847234246082599/subscription-plans')) {
				return res.send(nitro['521847234246082599']);
			} else if (url.includes('/590663762298667008/subscription-plans')) {
				return res.send(nitro['590663762298667008']);
			}
		}
		if (url.includes(api.subscriptions)) return res.send([]);
		if (url.includes(api.logout)) return res.status(204).send();
		const blacklist = [
			'entitlements/gifts',
			'outbound-promotions/codes',
			'entitlements',
			'experiments',
			'science',
			'affinities',
			'auth/',
			'applications/public',
			'notes',
			'roles/member-counts',
			'member-ids',
			'connections/configuration',
			'users/@me/mfa/totp',
			'users/@me/disable',
			'users/@me/delete',
			'users/@me/harvest',
		].some((path) => url.includes(path));

		if (blacklist) return res.status(403).send({ message: messages.CANNOT_USE_ENDPOINT });

		if (url.includes('oauth2/') && !url.includes('assets') && !url.includes('rpc')) {
			return res.status(403).send({ message: messages.CANNOT_USE_ENDPOINT });
		}
		if (url.includes(api.download)) return res.redirect('https://github.com/aiko-chan-ai/DiscordBotClient/releases');
		if (url.includes(api.hypesquad)) return res.status(204).send();
		if (url.includes('application-commands/search')) {
			return res.status(200).send({
				applications: [],
				application_commands: [],
				cursor: null,
			});
		} else if (url.includes('/profile')) {
			if (method === 'GET') {
				const url_ = new URL(apiBase + url);
				const id = url_.pathname.match(/\d{17,19}/) ? url_.pathname.match(/\d{17,19}/)[0] : '@me';
				// const guild_id = url_.searchParams.get('guild_id');
				axios.get(apiBase + api.users(id), { headers })
					.then(({ data }) => {
						const hasNitro = data.banner || data.avatar.startsWith('a_') || data.avatar_decoration;
						res.status(200).send({
							user: data,
							premium_since: hasNitro ? moment().format(dateFormat) : null,
							premium_type: hasNitro ? 2 : null,
							connected_accounts: []
						});
					})
					.catch((e) => res.status(404).send({ code: 10013, message: messages.UNKNOWN_USER }));
			} else if (method === 'PATCH') {
				const url_ = new URL(apiBase + url);
				const id = url_.pathname.match(/\d{17,19}/) ? url_.pathname.match(/\d{17,19}/)[0] : '@me';
				getDataFromRequest(req, res, (req) => {
					axios.patch(apiBase + api.users(id), req.rawBody, { headers })
						.then(({ data }) => res.status(200).send(data))
						.catch(({ code, status }) => res.status(500).send({ code, status }));
				});
			}
		} else if ([
			api.mentions, api.connections,
			'billing/',
			'activities/guilds',
			'interactions',
			'premium/subscription',
			'relationships',
			'store/published-listings/skus',
		].some((path) => url.includes(path))) return res.status(200).send([]);
		else if (url.includes('onboarding')) res.status(403).send(messages.CAN_PRETTY_MUCH_USE_ENDPOINT);
		else if (url.includes('/onboarding-responses') && method === 'POST') {
			const callback = (req, res) => {
				const guild_id = /\d{17,19}/.exec(url)[0];
				const user_id = Buffer.from(headers.Authorization.replace('Bot ', '').split('.')[0], 'base64').toString();
				let data = { ...req.body, guild_id, user_id };
				delete data.update_roles_and_channels;
				res.status(200).send(data);
			};
			return getDataFromRequest(req, res, callback);
		} else if (url.endsWith(api.searchMessages)) {
			const salt = Math.random().toString();
			const hash = crypto.createHash('md5').update(salt + text).digest('hex');
			return res.status(200).send({
				analytics_id: hash,
				doing_deep_historical_index: false,
				total_results: 0,
				messages: [],
			});
		} else if (url.endsWith(api.settingsProto(1))) {
			const uid = Buffer.from(headers.Authorization.replace('Bot ', '').split('.')[0], 'base64').toString();
			if (typeof cacheSettings.get(uid) === 'undefined') cacheSettings.set(uid, settingDefault);
			if (method === 'GET') return res.send({ settings: PreloadedUserSettings.toBase64(cacheSettings.get(uid).data1) });
			const callback = (req, res) => {
				const uid = Buffer.from(headers.Authorization.replace('Bot ', '').split('.')[0], 'base64').toString();
				if (typeof cacheSettings.get(uid) === 'undefined') cacheSettings.set(uid, settingDefault);
				const settings = cacheSettings.get(uid);
				const decoded = PreloadedUserSettings.fromBase64(req.body.settings);
				settings.data1 = Object.assign(settings.data1, decoded);
				cacheSettings.set(uid, settings);
				return res.send({
					settings: PreloadedUserSettings.toBase64(settings.data1),
				});
			};
			return getDataFromRequest(req, res, callback);
		} else if (url.endsWith(api.settingsProto(2))) return res.send({ settings: '' });
		else if (url.endsWith(api.emailSettings)) res.send(defaultDataEmailSetting);
		else if (url.endsWith(api.searchThreads(true))) {
			const cid = /\d{17,19}/.exec(url)[0];
			axios.get(apiBase + `/channels/${cid}/threads/archived/public`, { headers })
				.then((response) => {
					res.status(200).send(response.data);
				})
				.catch((err) => {
					res.status(400).send({
						message: err.message,
						error: err.stack,
						debug: {
							channelId: cid,
						},
					});
				});
		} else if (url.endsWith(api.me) && method === 'GET') {
			axios.get(apiBase + api.me, { headers })
				.then((response) => {
					let data = response.data;
					data.premium = true;
					data.premium_type = 1; // Nitro Classic
					data.mfa_enabled = 1; // Enable 2FA
					data.flags = '476111'; // All flags
					data.public_flags = '476111'; // All flags
					data.phone = '+1234567890'; // Fake phone
					data.verified = true; // verify
					data.nsfw_allowed = true; // Allow nsfw (iOS)
					data.email = 'DiscordBotClient@aiko.com'; // fake email, not a real one
					data.purchased_flags = 3;
					res.status(200).send(data);
				})
				.catch(() => res.status(404).send({ code: 10013, message: messages.UNKNOWN_USER }));
		} else if (url.endsWith(api.ask) || url.endsWith(api.ack)) return res.status(200).send({ token: null });
		else if (url.includes('billing/country-code')) res.status(200).send({ country_code: 'VN' });
		else if (url.includes('logout')) res.status(200).send();
		else return req.pipe(request('https://discord.com' + url)).pipe(res);
	};

	app.get(api.ping, function (req, res) {
		res.status(200).send('pong');
	});

	app.all('/d/*', function (req, res) {
		const str = req.originalUrl;
		const trs = str.slice('\x32');
		(0, logger?.info || console.log)('URL Request', trs);
		let headers = { 'User-Agent': userAgent };
		if (req.headers.authorization) headers.authorization = req.headers.authorization;
		Object.keys(req.headers).forEach((key) => {
			if (
				['cookie', 'x-', 'sec-', 'referer', 'origin', 'authorization', 'user-agent'].some((prefix) => key.toLowerCase().startsWith(prefix))
			) {} else { headers[key] = req.headers[key]; }
		});
		req.headers = headers;
		handlerRequest(trs, req, res);
	});
	app.all('/sticker*', function (req, res) {
		const str = req.originalUrl;
		const trs = str;
		req.pipe(request('https://discord.com' + trs)).pipe(res);
	});
	app.all('/asset*', function (req, res) {
		const str = req.originalUrl;
		const trs = str;
		(0, logger?.info || console.log)('Require Assets:', trs);
		if (trs.endsWith('.map')) {
			return res.status(404).send();
		}
		if (patchList.some((patch) => trs.endsWith(`${patch}.js`))) {
			res.set('Cache-Control', 'no-store');
			(0, logger?.info || console.log)('Load script target', trs);
			return res.send(
				scriptTarget[trs.replace('/assets/', '').replace('.js', '')],
			);
		}
		// see /assets/79d7e15ef9963457f52f.js
		/*
		axios
			.get('https://discord.com' + trs)
			.then((r) => {
				if (r.data.includes('_doIdentify')) {
					console.log('Found _doIdentify', trs);
					fs.writeFileSync(
						`./src/${trs.replace('/assets/', '')}`,
						r.data,
					);
				}
			})
			.catch((e) => {});
			*/
		req.pipe(request('https://discord.com' + trs)).pipe(res);
	});
	// Some request ...
	app.all('/oauth2/authorize', (req, res) => {
		res.redirect('/app');
	});

	app.all('/developers/*', (req, res) => {
		if (req.originalUrl.includes('developers/docs/intro')) {
			return res.redirect('https://discord.com/developers/docs/intro');
		} else {
			return res.redirect('/app');
		}
	});
	app.all('*', (req, res) => {
		if (req.originalUrl.endsWith('.map')) return res.status(404).send();
		res.send(html);
	});
};
