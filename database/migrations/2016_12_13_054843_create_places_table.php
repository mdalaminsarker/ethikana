<?php

use Illuminate\Support\Facades\Schema;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Migrations\Migration;

class CreatePlacesTable extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        Schema::create('places', function (Blueprint $table) {
            $table->increments('id');
            $table->integer('user_id')->unsigned();
            $table->string('longitude');
            $table->string('latitude');
            $table->text('Address');
            $table->string('city')->nullable();
            $table->string('area')->nullable();
            $table->integer('postCode')->nullable();
            $table->boolean('flag')->default(0);
            $table->string('device_ID')->nullable();
            $table->string('uCode')->unique();
            $table->string('pType')->nullable();
            $table->string('subType')->nullable();
            $table->tinyInteger('isRewarded')->nullable();
            $table->text('route_description')->nullable();
            $table->string('contact_person_name')->nullable();
            $table->string('contact_person_phone')->nullable();
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
        Schema::dropIfExists('places');
    }
}
