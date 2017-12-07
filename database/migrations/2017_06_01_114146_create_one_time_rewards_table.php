<?php

use Illuminate\Support\Facades\Schema;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Migrations\Migration;

class CreateOneTimeRewardsTable extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        Schema::create('one_time_rewards', function (Blueprint $table) {
            $table->increments('id');
            $table->integer('oneTimeRewardId')->unsigned();
            $table->integer('user_id')->unsigned();
            $table->foreign('oneTimeRewardId')->references('id')->on('rewards')->onDelete('cascade');
            $table->foreign('user_id')->references('id')->on('users')->onDelete('cascade');
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
        Schema::dropIfExists('one_time_rewards');
    }
}
