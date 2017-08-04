<?php
namespace Bootell\OAuth2\Client\Test\Provider;

use Bootell\OAuth2\Client\Provider\Wechat;
use Mockery;
use PHPUnit\Framework\TestCase;

class WechatTest extends TestCase
{
    /**
     * @var Wechat
     */
    protected $provider;

    protected function setUp()
    {
        $this->provider = new Wechat([
            'clientId' => 'APPID',
            'redirectUri' => 'REDIRECT_URI',
            'clientSecret' => 'SECRET',
        ]);
    }

    public function testGetAuthorizationUrl()
    {
        $params = [
            'appid' => 'APPID',
            'redirect_uri' => 'REDIRECT_URI',
            'response_type' => 'code',
            'scope' => uniqid(),
            'state' => uniqid(),
        ];
        parse_str(
            explode('?',
                $this->provider->getAuthorizationUrl(['scope' => $params['scope'], 'state' => $params['state']])
            )[1],
            $request
        );
        $this->assertArraySubset($params, $request);
    }

    public function testGetAccessToken()
    {
        $response = Mockery::mock('Psr\Http\Message\ResponseInterface');
        $response->shouldReceive('getBody')->andReturn('{"access_token":"ACCESS_TOKEN","expires_in":7200,"refresh_token":"REFRESH_TOKEN","openid":"OPENID","scope":"SCOPE"}');
        $response->shouldReceive('getHeader')->andReturn(['content-type' => 'json']);

        $client = Mockery::mock('GuzzleHttp\ClientInterface');
        $client->shouldReceive('send')->times(1)->andReturn($response);

        $this->provider->setHttpClient($client);
        $token = $this->provider->getAccessToken('authorization_code', ['code' => 'mock_authorization_code']);
        $this->assertEquals('ACCESS_TOKEN', $token->getToken());
        $this->assertLessThanOrEqual(time() + 7200, $token->getExpires());
        $this->assertGreaterThanOrEqual(time(), $token->getExpires());
        $this->assertEquals('REFRESH_TOKEN', $token->getRefreshToken());
        $this->assertNull($token->getResourceOwnerId());
    }

    public function testUserData()
    {
        $postResponse = Mockery::mock('Psr\Http\Message\ResponseInterface');
        $postResponse->shouldReceive('getBody')->andReturn('{"access_token":"ACCESS_TOKEN","expires_in":7200,"refresh_token":"REFRESH_TOKEN","openid":"OPENID","scope":"SCOPE"}');
        $postResponse->shouldReceive('getHeader')->andReturn(['content-type' => 'json']);

        $userResponse = Mockery::mock('Psr\Http\Message\ResponseInterface');
        $userResponse->shouldReceive('getBody')->andReturn('{"openid":"OPENID","nickname":"NICKNAME","sex":1,"province":"PROVINCE","city":"CITY","country":"COUNTRY","headimgurl":"http://wx.qlogo.cn/mmopen/g3MonUZtNHkdmzicIlibx6iaFqAc56vxLSUfpb6n5WKSYVY0ChQKkiaJSgQ1dZuTOgvLLrhJbERQQ4eMsv84eavHiaiceqxibJxCfHe/0","privilege":["PRIVILEGE1","PRIVILEGE2"],"unionid":"o6_bmasdasdsad6_2sgVt7hMZOPfL"}');
        $userResponse->shouldReceive('getHeader')->andReturn(['content-type' => 'json']);

        $client = Mockery::mock('GuzzleHttp\ClientInterface');
        $client->shouldReceive('send')
            ->times(2)
            ->andReturn($postResponse, $userResponse);

        $this->provider->setHttpClient($client);
        $token = $this->provider->getAccessToken('authorization_code', ['code' => 'mock_authorization_code']);
        $user = $this->provider->getResourceOwner($token);
        $this->assertEquals('OPENID', $user->getId());
        $this->assertEquals('NICKNAME', $user->getNickname());
        $this->assertEquals(1, $user->getSex());
        $this->assertEquals('PROVINCE', $user->getProvince());
        $this->assertEquals('CITY', $user->getCity());
        $this->assertEquals('COUNTRY', $user->getCountry());
        $this->assertEquals('http://wx.qlogo.cn/mmopen/g3MonUZtNHkdmzicIlibx6iaFqAc56vxLSUfpb6n5WKSYVY0ChQKkiaJSgQ1dZuTOgvLLrhJbERQQ4eMsv84eavHiaiceqxibJxCfHe/0', $user->getHeadImgUrl());
        $this->assertEquals(["PRIVILEGE1", "PRIVILEGE2"], $user->getPrivilege());
        $this->assertEquals('o6_bmasdasdsad6_2sgVt7hMZOPfL', $user->getUnionId());
    }

    public function testUserDataFails()
    {
        $error = '{"errcode":40003,"errmsg":"invalid openid"}';
        $test = function($error) {
            $postResponse = Mockery::mock('Psr\Http\Message\ResponseInterface');
            $postResponse->shouldReceive('getBody')->andReturn('{"access_token":"ACCESS_TOKEN","expires_in":7200,"refresh_token":"REFRESH_TOKEN","openid":"OPENID","scope":"SCOPE"}');
            $postResponse->shouldReceive('getHeader')->andReturn(['content-type' => 'json']);

            $userResponse = Mockery::mock('Psr\Http\Message\ResponseInterface');
            $userResponse->shouldReceive('getBody')->andReturn($error);
            $userResponse->shouldReceive('getHeader')->andReturn(['content-type' => 'json']);

            $client = Mockery::mock('GuzzleHttp\ClientInterface');
            $client->shouldReceive('send')
                ->times(2)
                ->andReturn($postResponse, $userResponse);
            $this->provider->setHttpClient($client);
            $token = $this->provider->getAccessToken('authorization_code', ['code' => 'mock_authorization_code']);
            try {
                $this->provider->getResourceOwner($token);
                return true;
            } catch (\Exception $e) {
                $this->assertInstanceOf('\League\OAuth2\Client\Provider\Exception\IdentityProviderException', $e);
                return false;
            }
        };
        $this->assertFalse($test($error));
    }
}