<?php

namespace SocialiteProviders\Telegram;

use Illuminate\Support\Facades\Validator;
use InvalidArgumentException;
use SocialiteProviders\Manager\OAuth2\AbstractProvider;
use SocialiteProviders\Manager\OAuth2\User;

class Provider extends AbstractProvider
{
    /**
     * Unique Provider Identifier.
     */
    const IDENTIFIER = 'TELEGRAM';

    /**
     * @return array
     */
    public static function additionalConfigKeys()
    {
        return [
            'bot',
        ];
    }

    /**
     * {@inheritdoc}
     */
    protected function getAuthUrl($state)
    {
        return null;
    }

    /**
     * {@inheritdoc}
     */
    protected function getTokenUrl()
    {
        return null;
    }

    /**
     * {@inheritdoc}
     */
    protected function getUserByToken($token)
    {
        return null;
    }

    public function getScript()
    {
        $botname = $this->config['bot'];
        $botId = $this->config['client_id'];
        $callbackUrl = $this->getConfig('redirect');


        return sprintf(
            '<script src="https://telegram.org/js/telegram-widget.js" data-auth-url="%s" data-request-access="write"></script>
            <script>
                document.querySelector("#telegram-login").addEventListener("click", event => {
                    window.Telegram.Login.auth(
                        {bot_id: "%s", request_access: true},
                        (data) => {
                            if (!data) {
                                console.error("authorization failed");
                                return;
                            }

                            fetch("%s", {
                                headers: {
                                    "Content-Type": "application/json",
                                    "Accept": "application/json",
                                    "X-Requested-With": "XMLHttpRequest",
                                    "X-CSRF-Token": document.querySelector("meta[name=csrf-token]").content
                                },
                                method: "post",
                                credentials: "same-origin",
                                body: JSON.stringify(data)
                            }).then(response => {
                                if (!response.redirected) {
                                    return;
                                }
                                window.location.href = response.url;
                            });
                        }
                    );
                });
            </script>',
            $botname,
            $botId,
            $callbackUrl
        );
    }

    /**
     * {@inheritdoc}
     */
    public function redirect()
    {
        return null;
    }

    /**
     * {@inheritdoc}
     */
    protected function mapUserToObject(array $user)
    {
        return (new User())->setRaw($user)->map([
            'id' => $user['id'],
            'nickname' => $user['username'],
            'name' => $user['first_name'] . ' ' . $user['last_name'],
            'avatar' => $user['photo_url'],
        ]);
    }

    /**
     * {@inheritdoc}
     */
    public function user()
    {
        $validator = Validator::make($this->request->all(), [
            'id' => 'required|numeric',
            'auth_date' => 'required|date_format:U|before:1 day',
            'hash' => 'required|size:64',
        ]);

        throw_if($validator->fails(), InvalidArgumentException::class);

        $dataToHash = collect($this->request->except('hash'))
            ->transform(function ($val, $key) {
                return "$key=$val";
            })
            ->sort()
            ->join("\n");

        $hash_key = hash('sha256', $this->config['client_secret'], true);
        $hash_hmac = hash_hmac('sha256', $dataToHash, $hash_key);

        throw_if(
            $this->request->hash !== $hash_hmac,
            InvalidArgumentException::class
        );

        return $this->mapUserToObject($this->request->except(['auth_date', 'hash']));
    }
}
