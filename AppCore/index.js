const {
	app,
	BrowserWindow,
	systemPreferences,
	shell,
	Notification,
	session,
} = require('electron');
const log = require('electron-log');
const path = require('path');
const fetch = require('node-fetch');
const { version: DBCVersion } = require('../package.json');
const { version: VencordVersion } = require('../Vencord/manifest.json');
const server = require('./server.js');

app.commandLine.appendSwitch('allow-insecure-localhost', 'true');
app.commandLine.appendSwitch('ignore-certificate-errors');
app.commandLine.appendSwitch('disable-features', 'OutOfBlinkCors');

const APP_NAME = 'DiscordBotClient';

app.setAppUserModelId(APP_NAME);

function createNotification(
	title,
	description,
	silent = false,
	callbackWhenClick,
) {
	const n = new Notification({
		title,
		body: description,
		icon: iconPath,
		silent,
	});
	n.once(
		'click',
		typeof callbackWhenClick === 'function'
			? () => {
					callbackWhenClick();
					n.close();
			  }
			: () => {
					n.close();
			  },
	);
	n.show();
}

log.info('App starting...');

const iconPath = path.join(__dirname, '..', 'AppAssets', 'DiscordBotClient.ico');

function checkUpdate() {
	log.info('Checking for updates...');
	return new Promise((resolve, reject) => {
		fetch(
			'https://api.github.com/repos/aiko-chan-ai/DiscordBotClient/releases/latest',
		)
			.then((res) => res.json())
			.then((res) => {
				if (res.tag_name !== DBCVersion) {
					createNotification(
						'Update Manager',
						`New version available: ${res.name}`,
						undefined,
						() => {
							shell.openExternal(
								'https://github.com/aiko-chan-ai/DiscordBotClient/releases',
							);
						},
					);
				} else {
					createNotification(
						'Update Manager',
						`You are using the latest version (v${DBCVersion})`,
					);
				}
			})
			.catch((e) => {
				log.error(e);
				createNotification(
					'Update Manager',
					`Unable to check for updates (v${DBCVersion})`,
					undefined,
					() => {
						shell.openExternal(
							'https://github.com/aiko-chan-ai/DiscordBotClient/releases',
						);
					},
				);
			})
            .finally(resolve);
	});
}

async function createWindow() {
	checkUpdate();
	// Create the browser window.
	const win = new BrowserWindow({
		width: 1920,
		height: 1080,
		icon: iconPath,
		webPreferences: {
			webSecurity: false,
			nodeIntegration: false,
			enableRemoteModule: false,
			contextIsolation: true,
		},
		title: 'DiscordBotClient',
		// titleBarStyle: "hidden",
	});

	log.info(`Electron UserData: ${app.getPath('userData')}`);

	// Create the server
	const port = await server(2023, log, win);

	createNotification('Proxy Server', `Proxy server started on port ${port}`);

	if (!app.isPackaged) win.webContents.openDevTools();

	if (systemPreferences && systemPreferences.askForMediaAccess)
		systemPreferences.askForMediaAccess('microphone');

	win.webContents.on('new-window', function (e, url) {
		e.preventDefault();
		return shell.openExternal(url);
	});

	const path_ = path.join(__dirname, '..', 'Vencord');

	win.setTitle(APP_NAME + ' Loading Vencord from ' + path_ + '...');
	await session.defaultSession.loadExtension(path_);
	log.info('Vencord-Web Extension loaded, version: ' + VencordVersion);

	win.loadURL(`https://localhost:${port}`);

	win.webContents.on('did-start-loading', () => {
		win.setProgressBar(2, { mode: 'indeterminate' }); // second parameter optional
	});

	win.webContents.on('did-stop-loading', () => {
		win.setTitle(APP_NAME);
		win.setProgressBar(-1);
	});

	session.defaultSession.webRequest.onHeadersReceived(
		{
			urls: ['https://raw.githubusercontent.com/*'],
		},
		(details, callback) => {
			// set content-type header to text/css
			details.responseHeaders['content-type'] = 'text/css';
			callback({ responseHeaders: details.responseHeaders });
		},
	);
}

app.whenReady().then(createWindow);

app.on('window-all-closed', () => {
	if (process.platform !== 'darwin') {
		app.quit();
	}
});

app.on('activate', () => {
	if (BrowserWindow.getAllWindows().length === 0) {
		createWindow();
	}
});

// before the app is terminated, clear both timers
app.on('before-quit', () => {
	log.info('App closing...');
});
