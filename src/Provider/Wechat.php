<?php
namespace Bootell\OAuth2\Client\Provider;

use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Token\AccessToken;
use Psr\Http\Message\ResponseInterface;

class Wechat extends AbstractProvider
{
    /**
     * 用户个人信息 国家地区语言版本
     *
     * @var string zh_CN|zh_TW|en
     */
    protected $language = 'zh-CN';

    /**
     * @inheritdoc
     */
    public function getBaseAuthorizationUrl()
    {
        return 'https://open.weixin.qq.com/connect/qrconnect';
    }

    /**
     * @inheritdoc
     */
    public function getBaseAccessTokenUrl(array $params)
    {
        return "https://api.weixin.qq.com/sns/oauth2/access_token";
    }

    /**
     * @inheritdoc
     */
    public function getResourceOwnerDetailsUrl(AccessToken $token)
    {
        return "https://api.weixin.qq.com/sns/userinfo?" . http_build_query([
            'access_token' => $token->getToken(),
            'openid' => $token->getValues()['openid'],
            'lang' => $this->language,
        ]);
    }

    /**
     * @inheritdoc
     */
    protected function getDefaultScopes()
    {
        return ['snsapi_login'];
    }

    /**
     * @inheritdoc
     * @link https://open.weixin.qq.com/cgi-bin/showdocument?action=dir_list&t=resource/res_list&verify=1&id=open1419318634&token=&lang=zh_CN
     */
    protected function checkResponse(ResponseInterface $response, $data)
    {
        if (isset($data['errcode']) && $data['errcode'] != 0) {
            throw new IdentityProviderException(
                $data['errmsg'] ?: $response->getReasonPhrase(),
                $data['errcode'],
                $response
            );
        }
    }

    /**
     * @inheritdoc
     */
    protected function createResourceOwner(array $response, AccessToken $token)
    {
        return new WechatResourceOwner($response);
    }

    /**
     * @inheritdoc
     */
    protected function getAuthorizationParameters(array $options)
    {
        $options = parent::getAuthorizationParameters($options);
        return [
            'appid' => $options['client_id'],
            'redirect_uri' => $options['redirect_uri'],
            'response_type' => 'code',
            'scope' => $options['scope'],
            'state' => $options['state'],
        ];
    }

    /**
     * @inheritdoc
     */
    protected function getAccessTokenMethod()
    {
        return self::METHOD_GET;
    }

    /**
     * @inheritdoc
     */
    protected function getAccessTokenBody(array $params)
    {
        $params['appid'] = $params['client_id'];
        $params['secret'] = $params['client_secret'];
        unset($params['client_id'], $params['client_secret'], $params['redirect_uri']);

        return $this->buildQueryString($params);
    }
}