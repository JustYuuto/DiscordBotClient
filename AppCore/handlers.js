const request = require('request');
const axios = require('axios');
const { PreloadedUserSettings } = require('discord-protos');
const crypto = require('crypto');
const Store = require('electron-store');

const settingDefault = require('../AppAssets/SettingProto');
const { version } = require('../package.json');

const NitroData = require('../AppAssets/NitroData');
const UserPatch = require('../AppAssets/UserPatch');
const Util = require('../AppAssets/Util');
const SystemMessages = require('../AppAssets/SystemMessages');
const messages = require('../AppAssets/Messages');
const api = require('../AppAssets/DiscordApi');
const { settingsProto } = require('../AppAssets/DiscordApi');

const userAgent = `DiscordBot Fork (https://github.com/JustYuuto/DiscordBotClient, v${version})`;
const discordApiBase = 'https://discord.com/api/v9';

const text = 'elysia-chan'; // idk :3

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

const handlerRequest = (url, req, res) => {
	const headers = {
		Authorization: req.headers['authorization'],
		'Content-Type': 'application/json',
		'User-Agent': userAgent
	};
	const method = req.method.toUpperCase();

	// Author:
    if (/users\/\d{17,19}/.exec(url)) {
		const id = url.match(/users\/(\d{17,19})/)[1];
		const UserData = UserPatch[id];
		if (url.includes('profile') && UserData) {
			return res.send(Util.ProfilePatch(UserData));
		} else if (UserData) {
			return res.send(UserData);
		}
	}
	if (url.includes(api.channelMessages('1000000000000000000'))) return res.send(SystemMessages);
    if (url.includes('voice-channel-effects')) {
		return res.status(200).send();
	}
	// Store
	if (url.includes('store/published-listings/skus/')) {
        const id = url.match(/(\d{17,19})\/subscription-plans/)[1];
        return res.send(NitroData[id]);
	}
	if (url.includes(api.subscriptions) || url.includes(api.gifts)) return res.send([]);
	if (url.includes('auth/logout')) return res.status(204).send();
	const blacklist = [
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
		'connections/eligibility',
		'activities/shelf',
	].some((path) => url.includes(path));
	if (blacklist) return res.status(404).send({ message: messages.CANNOT_USE_ENDPOINT });
	if (
		url.includes('oauth2/') && !url.includes('assets') && !url.includes('rpc')
	) return res.status(404).send({ message: messages.CANNOT_USE_ENDPOINT });
	if (url.includes(api.download)) return res.redirect('https://github.com/aiko-chan-ai/DiscordBotClient/releases');
	if (url.includes(api.hypesquad)) return res.status(204).send();
	if (url.includes('application-commands/search')) {
		return res.status(200).send({
			applications: [],
			application_commands: [],
			cursor: null,
		});
	}
    if (url.match(/\/users\/([0-9]{17,19}|%40me)\/profile/gi)) {
		const url_ = new URL(`https://discord.com${url}`);
		const id =  url_.pathname.match(/\d{17,19}/) ? url_.pathname.match(/\d{17,19}/)[0] : '@me';
		if (method === 'GET') {
			return axios.get(discordApiBase + api.users(id), { headers })
				.then(({ data }) => res.status(200).send(Util.ProfilePatch(data)))
				.catch(() => res.status(200).send(Util.ProfilePatch({ id })));
		} else if (method === 'PATCH') {
			return getDataFromRequest(req, res, ({ rawBody }) => {
				return axios.patch(discordApiBase + api.users(id), rawBody, { headers })
					.then(({ data }) => res.status(200).send(Util.ProfilePatch(data)))
					.catch(() => res.status(200).send(Util.ProfilePatch({ id })));
			});
		}
	}
    if ([
		api.mentions,
		'billing/',
		'activities/guilds',
		'interactions',
		'premium/subscription',
		'relationships',
		'store/published-listings/skus',
		'outbound-promotions/codes'
	].some((path) => url.includes(path))) return res.status(200).send([]);
    if (url.includes('onboarding')) {
		return res.status(400).send(messages.CAN_PRETTY_MUCH_USE_ENDPOINT);
	}
    if (url.includes('/onboarding-responses') && method === 'POST') {
		const callback = (req, res) => {
			const guild_id = /\d{17,19}/.exec(url)[0];
			const uid = Buffer.from(headers.Authorization.replace('Bot ', '').split('.')[0], 'base64').toString();
			let data = {
				...req.body,
				guild_id,
				user_id: uid,
			};
			delete data.update_roles_and_channels;
			res.status(200).send(data);
		};
		return getDataFromRequest(req, res, callback);
	}
    if (url.includes(api.searchMessages)) {
		const salt = Math.random().toString();
		const hash = crypto.createHash('md5').update(salt + text).digest('hex');
		return res.status(200).send({
			analytics_id: hash,
			doing_deep_historical_index: false,
			total_results: 0,
			messages: [],
		});
	}
    if (url.includes(api.settingsProto(1))) {
		// parse userid from header
		const uid = Buffer.from(headers.Authorization.replace('Bot ', '').split('.')[0], 'base64').toString();
		if (typeof cacheSettings.get(uid) === 'undefined') cacheSettings.set(uid, settingDefault);
		if (method === 'GET')
			return res.send({
				settings: PreloadedUserSettings.toBase64(cacheSettings.get(uid).data1),
			});
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
	}
    if (url.includes(api.settingsProto(2))) return res.send({ settings: '' });
    if (url.includes(api.emailSettings)) return res.send(defaultDataEmailSetting);
    if (url.includes(api.searchThreads(true))) {
        // TODO: fix this
		const cid = /\d{17,19}/.exec(url)[0];
		return axios.get(discordApiBase + `/channels/${cid}/threads/archived/public`, { headers })
			.then((response) => {
				res.status(200).send({
					...response.data,
					total_results: response.data.threads?.length || 0,
				});
			})
			.catch((err) => {
				res.status(404).send({
					message: err.message,
					error: err.stack,
					debug: {
						channelId: cid,
					},
				});
			});
	}
    if (url.endsWith(api.me)) {
		if (method === 'GET') {
			return axios.get(discordApiBase + api.me, { headers })
				.then((response) => {
					let data = response.data;
					data.premium = true;
					data.premium_type = 2; // Nitro Boost
					data.mfa_enabled = 1; // Enable 2FA
					data.flags = '476111'; // All flags
					data.public_flags = '476111'; // All flags
					data.phone = '+1234567890'; // Fake phone
					data.verified = true; // verify
					data.nsfw_allowed = true; // Allow nsfw (ios)
					data.email = 'DiscordBotClient@aiko.com'; // fake email, not a real one
					data.purchased_flags = 3;
					res.status(200).send(data);
				})
				.catch((err) => res.status(404).send());
		} else if (method === 'PATCH') {
			return getDataFromRequest(req, res, ({ rawBody }) => {
				return axios.patch(discordApiBase + api.me, rawBody, { headers })
					.then((response) => {
						let data = response.data;
						data.premium = true;
						data.premium_type = 2; // Nitro Boost
						data.mfa_enabled = 1; // Enable 2FA
						data.flags = '476111'; // All flags
						data.public_flags = '476111'; // All flags
						data.phone = '+1234567890'; // Fake phone
						data.verified = true; // verify
						data.nsfw_allowed = true; // Allow nsfw (ios)
						data.email = 'DiscordBotClient@aiko.com'; // fake email, not a real one
						data.purchased_flags = 3;
						res.status(200).send(data);
					})
					.catch((err) => res.status(404).send());
			});
		}
	}
    if (url.endsWith(api.ack)) return res.status(200).send({ token: null });
    if (url.includes('billing/country-code')) return res.status(200).send({ country_code: 'VN' });
    if (url.includes('logout')) return res.status(200).send();
    return req.pipe(request('https://discord.com' + url)).pipe(res);
};

module.exports = function (app, logger, html, patchList, scriptTarget) {
	app.get(api.ping, function (req, res) {
		res.status(200).send('pong');
	});

	app.all('/d/*', function (req, res) {
		const str = req.originalUrl;
		const trs = str.slice('\x32');
		let headers = { 'User-Agent': userAgent };
		if (req.headers.authorization) headers.authorization = req.headers.authorization;
		Object.keys(req.headers).forEach((key) => {
			if ([
				'cookie',
				'x-',
				'sec-',
				'referer',
				'origin',
				'authorization',
				'user-agent',
			].some((prefix) => key.toLowerCase().startsWith(prefix))) {
				return;
			} else {
				headers[key] = req.headers[key];
			}
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
		return req.pipe(request('https://discord.com' + trs)).pipe(res);
	});

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
