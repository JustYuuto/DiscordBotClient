module.exports = {
  me: '/users/@me',
  connections: '/users/@me/connections',
  users: (id) => `/users/${id}`,
  profile: (id) => `/users/${id}/profile`,
  channelMessages: (id) => `/channels/${id}/messages`,
  subscriptions: '/billings/subscriptions',
  logout: '/auth/logout',
  download: '/download',
  hypesquad: '/hypesquad/online',
  mentions: '/users/@me/mentions',
  searchMessages: '/messages/search',
  emailSettings: '/users/@me/email-settings',
  settingsProto: (n) => `/settings-proto/${n}`,
  searchThreads: (archived) => `/threads/search?archived=${(typeof archived === 'boolean' ? archived : false).toString()}`,
  ping: '/ping',
  ack: '/ack',
  ask: '/ask'
};
