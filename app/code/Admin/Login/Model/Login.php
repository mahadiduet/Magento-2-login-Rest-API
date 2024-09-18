<?php
namespace Admin\Login\Model;

use Admin\Login\Api\LoginInterface;
use Magento\Customer\Api\AccountManagementInterface;
use Magento\Customer\Api\CustomerRepositoryInterface;
use Magento\Framework\App\Request\Http;
use Magento\Framework\HTTP\Client\Curl;
use Magento\Customer\Model\CustomerFactory;
use Magento\Framework\Exception\LocalizedException;
use Magento\Framework\Event\ManagerInterface;
use Magento\Integration\Model\Oauth\TokenFactory as TokenModelFactory;
use Magento\Framework\App\Request\ThrottlerInterface;

class Login implements LoginInterface
{

    const API_ENDPOINT = 'http://bdodev.sindabad.com/api/v1/outlet/verification';
    /**
     * @var AccountManagementInterface
     */
    private $accountManagement;

    /**
     * @var CustomerRepositoryInterface
     */
    private $customerRepository;

    protected $request;
    protected $curl;
    protected $customerFactory;
    protected $eventManager;
    private $tokenModelFactory;
    private $customTokenService;

    /**
     * Token constructor.
     *
     * @param AccountManagementInterface $accountManagement
     * @param CustomerRepositoryInterface $customerRepository
     */
    public function __construct(
        AccountManagementInterface $accountManagement,
        CustomerRepositoryInterface $customerRepository,
        Http $request,
        Curl $curl,
        CustomerFactory $customerFactory,
        ManagerInterface $eventManager,
        TokenModelFactory $tokenModelFactory
    ) {
        $this->accountManagement = $accountManagement;
        $this->customerRepository = $customerRepository;
        $this->request = $request;
        $this->curl = $curl;
        $this->customerFactory = $customerFactory;
        $this->eventManager = $eventManager;
        $this->tokenModelFactory = $tokenModelFactory;
    }

    /**
     * {@inheritdoc}
     */
    public function login($token_code, $store_code, $store_email)
    {
        try {
            $customerDataObject = $this->authenticate($store_email);
            $verify = $this->verifyTokenAndEmailOnOtherServer($token_code, $store_code, $store_email);
            /*$this->getRequestThrottler()->resetAuthenticationFailuresCount($username, RequestThrottler::USER_TYPE_CUSTOMER);*/
            if($verify['verified']== true && $customerDataObject)
                return $this->tokenModelFactory->create()->createCustomerToken($customerDataObject->getId())->getToken();

        } catch (AuthenticationException $e) {
            return null;
        }
    }


    public function authenticate($username, $password = "")
    {
        try {
            $customer = $this->customerRepository->get($username);
        } catch (NoSuchEntityException $e) {
            throw new InvalidEmailOrPasswordException(__('Invalid login or password.'));
        }

        $customerId = $customer->getId();
        /*if ($this->getAuthentication()->isLocked($customerId)) {
            throw new UserLockedException(__('The account is locked.'));
        }*/

        if ($customer->getConfirmation() && $this->isConfirmationRequired($customer)) {
            throw new EmailNotConfirmedException(__('This account is not confirmed.'));
        }

        $customerModel = $this->customerFactory->create()->updateData($customer);
        $this->eventManager->dispatch(
            'customer_customer_authenticated',
            ['model' => $customerModel, 'password' => $password]
        );
        $this->eventManager->dispatch('customer_data_object_login', ['customer' => $customer]);

        return $customer;
    }

    private function getAuthentication()
    {
        if (!($this->authentication instanceof AuthenticationInterface)) {
            return \Magento\Framework\App\ObjectManager::getInstance()->get(
                \Magento\Customer\Model\AuthenticationInterface::class
            );
        } else {
            return $this->authentication;
        }
    }

    public function verifyTokenAndEmailOnOtherServer($token_code, $store_code, $store_email)
    {
        $url = 'http://bdodev.sindabad.com/api/v1/outlet/verification';
        $headers = [
            'Content-Type: application/json',
            'Authorization: '.$token_code
        ];
        $payload = [
            'store_code' => $store_code,
            'store_email' => $store_email
        ];

        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($payload));

        $response = curl_exec($ch);
        $responseData = json_decode($response, true);

        if ($response === false || !$responseData) {
            return null;
        }
        return $responseData;
    }
}
