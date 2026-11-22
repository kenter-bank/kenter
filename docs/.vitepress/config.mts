import { defineConfig } from 'vitepress'
import { withMermaid } from 'vitepress-plugin-mermaid'

// The Kenter documentation site: how the system works, and how to build,
// run, test and deploy it.
export default withMermaid(
  defineConfig({
    title: 'Kenter',
    description: 'Documentation for the Kenter workspace',
    lang: 'en',
    // Served from a file:// build as well as a dev server, so links must
    // not assume a domain.
    base: '/',
    cleanUrls: false,
    lastUpdated: true,
    // systest-runs/ holds local per-run logs with addresses and observed
    // ledger values. They are gitignored for that reason, and must not
    // be rendered into a site that might be published. node_modules is
    // excluded because VitePress would otherwise walk every README in
    // it.
    srcExclude: ['systest-runs/**', 'node_modules/**', 'README.md'],
    // Pages may point at source files outside docs/.
    ignoreDeadLinks: [/^\.\.\/\.\.\/crates/, /^\.\.\/\.\.\/contracts/],

    themeConfig: {
      nav: [
        { text: 'Architecture', link: '/architecture/overview' },
        { text: 'Reference', link: '/reference/index' },
        { text: 'Testing', link: '/testing/index' },
        { text: 'Runbook', link: '/runbook/setup' },
      ],

      sidebar: [
        {
          text: 'Start here',
          items: [
            { text: 'What Kenter is', link: '/index' },
            { text: 'Reading guide', link: '/reading-guide' },
          ],
        },
        {
          text: 'Architecture',
          collapsed: false,
          items: [
            { text: 'System overview', link: '/architecture/overview' },
            { text: 'The workspace', link: '/architecture/crates' },
            { text: 'Custody and keys', link: '/architecture/custody' },
            { text: 'Tokens and their lifecycle', link: '/architecture/tokens' },
            { text: 'Node selection', link: '/architecture/node-selection' },
            { text: 'Bearer and spend mode', link: '/architecture/spend-mode' },
            { text: 'Network and contracts', link: '/architecture/network' },
            { text: 'Security model', link: '/architecture/security-model' },
            { text: 'Data formats', link: '/architecture/data-formats' },
            { text: 'Bearer token format', link: '/bearer-token-format' },
            { text: 'The desktop client', link: '/architecture/client' },
          ],
        },
        {
          text: 'Crate reference',
          collapsed: false,
          items: [
            { text: 'Index', link: '/reference/index' },
            { text: 'kenter-crypto', link: '/reference/kenter-crypto' },
            { text: 'kenter-vault', link: '/reference/kenter-vault' },
            { text: 'kenter-wallet', link: '/reference/kenter-wallet' },
            { text: 'kenter-network', link: '/reference/kenter-network' },
            { text: 'kenter-client', link: '/reference/kenter-client' },
            { text: 'kenter-ui', link: '/reference/kenter-ui' },
            { text: 'stellar-keycard', link: '/reference/stellar-keycard' },
            { text: 'Supporting crates', link: '/reference/supporting' },
          ],
        },
        {
          text: 'Testing',
          collapsed: false,
          items: [
            { text: 'The harnesses', link: '/testing/index' },
            { text: 'Paper and camera', link: '/testing/paper' },
            { text: 'Keycard hardware', link: '/testing/keycard' },
            { text: 'System tests', link: '/testing/systest' },
          ],
        },
        {
          text: 'Operations',
          collapsed: false,
          items: [
            { text: 'Testnet environment', link: '/TESTNET' },
            { text: 'Ledger costs and fees', link: '/LEDGER_COSTS' },
            { text: 'Local system test', link: '/SYSTEM_TEST' },
            { text: 'Deployment', link: '/DEPLOY' },
            { text: 'Relay API', link: '/tunnler-api' },
          ],
        },
        {
          text: 'Runbook',
          collapsed: false,
          items: [
            { text: 'Setting up', link: '/runbook/setup' },
            { text: 'Build and run', link: '/runbook/build-and-run' },
            { text: 'A local network', link: '/runbook/local-network' },
            { text: 'Running the tests', link: '/runbook/testing' },
            { text: 'When things break', link: '/runbook/troubleshooting' },
            { text: 'Releases', link: '/runbook/releases' },
          ],
        },
      ],

      outline: { level: [2, 3] },
      search: { provider: 'local' },
      docFooter: { prev: true, next: true },
    },
  }),
)
