<?php
/*
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * OPNsense UI controller for the TrustForge plugin.
 *
 * Renders /trustforge/ — a single-page Volt template that talks to
 * the Api/SettingsController via the standard OPNsense AJAX helpers.
 */

namespace OPNsense\Trustforge;

use OPNsense\Base\IndexController as BaseController;

class IndexController extends BaseController
{
    public function indexAction()
    {
        // Bind the model XML so the Volt template can iterate fields.
        $this->view->generalForm = $this->getForm('general');
        $this->view->bridgesForm = $this->getForm('bridges');

        // Pass through static metadata used by the template header.
        $this->view->title       = gettext('TrustForge');
        $this->view->description = gettext(
            'TrustForge identity, capability, and proof daemon. ' .
            'Edit settings here; click Apply to render config.yaml ' .
            'and reload the daemon.'
        );

        $this->view->pick('OPNsense/Trustforge/index');
    }
}
