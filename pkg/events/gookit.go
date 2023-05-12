/**
 *
 * (c) Copyright Ascensio System SIA 2023
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

package events

import (
	"github.com/gookit/event"
)

type gooKitEmitter struct{}

func NewGoKitEmitter() Emitter {
	return &gooKitEmitter{}
}

func (g gooKitEmitter) On(name string, listener Listener) {
	event.On(name, event.ListenerFunc(func(e event.Event) error {
		return listener.Handle(e)
	}))
}

func (g gooKitEmitter) Fire(name string, payload map[string]any) {
	event.Fire(name, payload)
}
