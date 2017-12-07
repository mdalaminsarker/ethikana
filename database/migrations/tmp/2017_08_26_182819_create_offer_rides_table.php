<?php

use Illuminate\Support\Facades\Schema;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Migrations\Migration;

class CreateOfferRidesTable extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        Schema::create('offer_rides', function (Blueprint $table) {
            $table->increments('id');
            $table->integer('user_id')->unsigned();
            $table->integer('vehicle_id')->unsigned();
            $table->time('startTime');//apporox
            $table->string('startLat');
            $table->string('startLon');
            $table->text('startAddress');
            $table->string('endLat');
            $table->string('endLon');
            $table->text('endAddress');
            $table->integer('shared_seat_number');
            $table->tinyInteger('isActive');
            $table->tinyInteger('isAvailable')->default(1);
            $table->foreign('vehicle_id')->references('id')->on('pool_vehicles')->onDelete('cascade');  
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
        Schema::dropIfExists('offer_rides');
    }
}
