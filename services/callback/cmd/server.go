/**
 *
 * (c) Copyright Ascensio System SIA 2024
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package cmd

import (
	"github.com/ONLYOFFICE/onlyoffice-box/services/callback/web"
	"github.com/ONLYOFFICE/onlyoffice-box/services/callback/web/controller"
	"github.com/ONLYOFFICE/onlyoffice-box/services/shared"
	"github.com/ONLYOFFICE/onlyoffice-box/services/shared/format"
	pkg "github.com/ONLYOFFICE/onlyoffice-integration-adapters"
	chttp "github.com/ONLYOFFICE/onlyoffice-integration-adapters/service/http"
	"github.com/urfave/cli/v2"
)

func Server() *cli.Command {
	return &cli.Command{
		Name:     "server",
		Usage:    "starts a new http server instance",
		Category: "server",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "config_path",
				Usage:   "sets custom configuration path",
				Aliases: []string{"config", "conf", "c"},
			},
		},
		Action: func(c *cli.Context) error {
			var (
				CONFIG_PATH = c.String("config_path")
			)

			app := pkg.NewBootstrapper(
				CONFIG_PATH, pkg.WithModules(
					chttp.NewService, web.NewServer,
					shared.BuildNewOnlyofficeConfig(CONFIG_PATH),
					shared.BuildNewIntegrationCredentialsConfig(CONFIG_PATH),
					controller.NewCallbackController,
					shared.NewBoxAPIClient,
					format.NewMapFormatManager,
				)).Bootstrap()

			if err := app.Err(); err != nil {
				return err
			}

			app.Run()

			return nil
		},
	}
}
