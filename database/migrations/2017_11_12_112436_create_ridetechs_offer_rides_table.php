<?php

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Migrations\Migration;

class CreateRidetechsOfferRidesTable extends Migration
{

    public function up()
    {
        Schema::create('ridetechs_offer_rides', function(Blueprint $table) {
            $table->increments('id');
            $table->string('start_point')->nullable();
            $table->string('destination')->nullable();
            $table->time('pickup_time')->nullable();
            $table->time('dropoff_time')->nullable();
            $table->string('day_in_week')->nullable();
            $table->string('car_model')->nullable();
            $table->string('name')->nullable();
            $table->string('number')->nullable();
            $table->integer('user_id')->unsigned();
            $table->foreign('user_id')->references('id')->on('users');
            $table->timestamps();


        });
    }

    public function down()
    {
        Schema::drop('ridetechs_offer_rides');
    }
}
