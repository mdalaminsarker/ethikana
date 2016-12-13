<?php

use Illuminate\Database\Seeder;

class UserTableSeeder extends Seeder
{
    /**
     * Run the database seeds.
     *
     * @return void
     */
    public function run()
    {
        DB::table('users')->insert([
            'name' => 'Tayef',
            'email' => 'tayef56@yahoo.com',
            'password' => app('hash')->make('tayef56'),
            'remember_token' => str_random(10),
        ]);
    }
}
