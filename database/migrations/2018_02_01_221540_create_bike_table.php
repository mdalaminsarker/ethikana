<?php

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Migrations\Migration;

class CreateBikeTable extends Migration
{

    public function up()
    {
        Schema::create('Bike', function(Blueprint $table) {
            $table->increments('id');
            $table->string('model_name');
            $table->integer('model_year');
            $table->integer('engine_capacity');
            $table->string('registration_number');
            $table->string('engine_number')->nullable();// for admin
            $table->string('chassis_number')->nullable();// for admin
            $table->string('bike_image_link')->nullable();
            $table->string('paper_image_link')->nullable(); // for admin
            $table->integer('hourly_rent');
            $table->integer('daily_rent')->nullable();
            $table->integer('user_id')->unsigned();
            $table->dateTime('last_serviced')->nullable(); // for admin
            $table->dateTime('next_service')->nullable(); // for admin
            $table->tinyInteger('availability')->default(0);
            $table->foreign('user_id')->references('id')->on('users');
            $table->timestamps();

            // Schema declaration
            // Constraints declaration

        });
    }

    public function down()
    {
        Schema::drop('Bike');
    }
}
