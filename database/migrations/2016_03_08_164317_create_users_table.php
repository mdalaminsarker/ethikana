<?php

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Migrations\Migration;

class CreateUsersTable extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        Schema::create('users', function (Blueprint $table) {
            $table->increments('id');                                   //1
            $table->string('name');                                     //2
            $table->string('email')->unique();
            $table->string('password', 60);
            $table->string('phone')->unique();
            $table->integer('userType');
            $table->integer('total_points')->default(10);
            $table->integer('redeemed_points');
            $table->tinyInteger('isReferred')->default(0);
            $table->string('device_ID')->unique()->nullable();
            $table->string('ref_code')->unique()->nullable();
            $table->tinyInteger('hasPendingRewardRequest')->default(0); //12
            $table->tinyInteger('canHaveApiKey')->default(0);
            $table->tinyInteger('isPoolProvider')->default(0);
            $table->string('user_last_lon')->nullable();
            $table->string('user_last_lat')->nullable();
            $table->rememberToken();
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        Schema::drop('users');
    }
}
