# boneuserapi
BoneUserApi package for Bone Mvc Framework
## installation
Use Composer
```
composer require delboy1978uk/bone-user-api
```
## usage
Simply add to the `config/packages.php`
```php
<?php

// use statements here
use Bone\BoneUserApi\BoneUserApiPackage;

return [
    'packages' => [
        // packages here...,
        BoneUserApiPackage::class,
    ],
    // ...
];
```