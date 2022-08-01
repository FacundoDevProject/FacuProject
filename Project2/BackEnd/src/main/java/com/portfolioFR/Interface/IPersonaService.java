package com.portfolioFR.Interface;

import com.portfolioFR.Entity.Persona;
import java.util.List;

public interface IPersonaService {
    //Traer una lista de personas
    public List<Persona> getPersona();
    
    //Guarda un objeto de tipo persona
    public void savePersona(Persona persona);
    
    //Eliminar un objeto buscandolo por ID
    public void deletePersona(Long id);
    
    //Buscar persona por ID
    public Persona findPersona(Long id);   
}
