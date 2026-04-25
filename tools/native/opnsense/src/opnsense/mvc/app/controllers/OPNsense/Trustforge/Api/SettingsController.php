<?php
/*
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * OPNsense REST controller for TrustForge plugin settings.
 *
 * Endpoints (all under /api/trustforge/settings):
 *
 *   GET  /get             — fetch full settings tree
 *   POST /set             — replace settings tree (validated by model)
 *   POST /reconfigure     — render config.yaml + reload tf-daemon
 *   GET  /status          — daemon liveness + decision histogram
 *
 * OPNsense's ApiMutableModelControllerBase wires the GET/POST helpers
 * automatically once $internalModelClass / $internalModelName are
 * declared.
 */

namespace OPNsense\Trustforge\Api;

use OPNsense\Base\ApiMutableModelControllerBase;
use OPNsense\Core\Backend;

class SettingsController extends ApiMutableModelControllerBase
{
    protected static $internalModelName  = 'trustforge';
    protected static $internalModelClass = '\OPNsense\Trustforge\Trustforge';

    /**
     * GET /api/trustforge/settings/get
     * Inherited getAction() returns the full model tree as JSON.
     */

    /**
     * POST /api/trustforge/settings/set
     * Inherited setAction() validates the payload against the model
     * XML schema and persists to OPNsense's config.xml.
     */

    /**
     * POST /api/trustforge/settings/reconfigure
     *
     * Re-render /usr/local/etc/trustforge/config.yaml from the live
     * config tree and ask configd to restart the service. This is the
     * canonical "apply changes" action exposed to the web UI.
     */
    public function reconfigureAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'failed', 'message' => 'POST required'];
        }

        // Re-render YAML from config.xml
        require_once '/usr/local/etc/inc/plugins.inc.d/trustforge.inc';
        if (function_exists('trustforge_render_config')) {
            trustforge_render_config();
        }

        $backend = new Backend();
        $running = trim($backend->configdRun('trustforge status')) === 'running';
        $verb    = $running ? 'restart' : 'start';
        $out     = trim($backend->configdRun("trustforge {$verb}"));

        return [
            'status'  => 'ok',
            'action'  => $verb,
            'message' => $out,
        ];
    }

    /**
     * GET /api/trustforge/settings/status
     *
     * Liveness, profile, and decision histogram. The web UI polls
     * this every few seconds.
     */
    public function statusAction()
    {
        $backend = new Backend();

        $svc = trim($backend->configdRun('trustforge status'));
        $hist = json_decode(
            trim($backend->configdRun('trustforge histogram')) ?: '{}',
            true
        ) ?: ['allow' => 0, 'deny' => 0, 'ask' => 0];
        $info = json_decode(
            trim($backend->configdRun('trustforge info')) ?: '{}',
            true
        ) ?: [];

        return [
            'running'   => ($svc === 'running'),
            'service'   => $svc,
            'profile'   => $info['profile'] ?? null,
            'actor'     => $info['actor']   ?? null,
            'histogram' => $hist,
        ];
    }
}
