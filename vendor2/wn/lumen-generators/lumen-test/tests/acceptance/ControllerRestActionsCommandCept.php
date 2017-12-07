<?php
$I = new AcceptanceTester($scenario);

$I->wantTo('generate the REST actions trait');
$I->runShellCommand('php artisan wn:controller:rest-actions --force=true');
$I->seeInShellOutput('REST actions trait generated');
$I->seeFileFound('./app/Http/Controllers/RESTActions.php');
$I->openFile('./app/Http/Controllers/RESTActions.php');
$I->seeInThisFile('trait RESTActions {');
$I->deleteFile('./app/Http/Controllers/RESTActions.php');
